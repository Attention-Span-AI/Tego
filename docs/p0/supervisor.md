# internal/runtime/supervisor (P0 detailed spec)

## 1. Purpose and boundaries

**Owns.** The seccomp user-notification loop that backs tier 1 (`landlock`) and augments tier 2 (`cgroup`): draining
`SECCOMP_IOCTL_NOTIF_RECV` on the notify fd handed up by `launch.Child.WaitNotifyFD`/`pidfd_getfd`; dispatching each
notification by `(arch, nr)`; reading target-process arguments safely; making the **connect** verdict (the only
verdict this package is authoritative for, per P0-DESIGN §2.7: "decisions for connect, record for the rest"), which
per spec/backend/CAPABILITIES.md's "unix sockets" row covers AF_UNIX as well as TCP/UDP (R11); recording
write-opens, unlink, rename, mkdir, symlink as advisory events while answering `CONTINUE`; deciding exec (R16,
R16b): an exec it matches to a grant is `CONTINUE`d for Landlock's `EXECUTE` bit to decide on the inode, and every
other exec it refuses itself, so an exec line never reads `refused` for an exec that was continued; refusing the
syscalls no tier below tier 3 can otherwise reach — the mount family (R31) and, unless the contract declares
`keyring: true`, the kernel keyring (R32); responding to every notification exactly once; counting `notifications`
and `held_ms` for `run_end.supervisor`.

**Must not do.**
- Enforce anything Landlock/fanotify already enforces (write-opens, deletes, renames, mkdir, symlink) — this
  package's role there is record-only; a `CONTINUE` here is never a grant. Exec is the exception (R16b): this
  loop refuses, in front of Landlock, every exec it cannot match to a grant, so the ledger never records `refused`
  for an exec that ran (recording a refusal Landlock was trusted to make would). A
  `CONTINUE` is still never a grant there: Landlock's `EXECUTE` bit decides every exec this loop continues. The
  built-in `deny_write` set is the other (R15c), since Landlock cannot refuse beneath a write entry at all.
- Answer an ask itself: a hold for a person is carried out here for ask scopes (R7a's held opens, R11c's connects,
  R13d's datagrams), and the answer comes through `internal/runtime/ask`.
- Read the eBPF ring buffer (`observe`), parse model traffic (`capture`/`derive`), write the ledger directly
  (`ledger`), or evaluate the gate (P1) — it only produces `record.Event` values onto a `Sink`.
- Build the BPF filter program itself — `api.Handle.SeccompFilter()` (`enforce/landlock`, `enforce/cgroup`)
  constructs and attaches it; this package only owns the fd once installed.

**Imports allowed:** `golang.org/x/sys/unix` (ioctls, `process_vm_readv`, `Sockaddr` parsing), `internal/platform/proc`
(`/proc/<pid>/{mem,fd,cwd,root,status}` helpers), `pkg/spec/record` (`Event`, `Kind`, `Verdict`, `Source`, `Reason`),
`pkg/spec/agent` (net rule shapes feeding `Policy`), standard library (`context`, `sync/atomic`, `time`).
**Must not import:** `internal/ledger`, `internal/check`, `internal/serve`, `internal/runtime/observe`,
`internal/runtime/capture/*`, `internal/runtime/derive/*`, `internal/runtime/enforce/*` (it consumes a compiled
`*agent.RuleTable`/`Policy` value handed to it, never the backend), `cilium/ebpf` (no BPF maps live here; tier 2's
maps belong to `enforce/cgroup`).

**Changes.**
- 2026-10-25, R15 (ADR 0067 D3): a read, or an
  unrestricted exec, at or beneath an absent built-in row's left-out name is recorded refused, `read_denied`, by the row.
- 2026-09-23, Must not do (R16b): exec is refused in front of Landlock when no grant matches.
- 2026-10-25, R16b (ADR 0064): the harness hook's exact-argv grant is decided here like any exec rule; every other
  vector of the tego binary is refused under `exec.harness-hook[<tego binary>]`.

## 2. Models

```go
package supervisor // internal/runtime/supervisor — the shapes below are the code's, fields abridged

// Loop drains one seccomp notify fd with a bounded worker pool (New, Run).
type Loop struct {
    k        kernel                    // syscall seam over the notify fd from pidfd_getfd; not created here
    table    atomic.Pointer[compiled]  // the decision table, compiled once in New and never swapped (I9, R27)
    sink     Sink                      // record.Event consumer; called only after the answer is sent (R23)
    workers  int                       // bounded pool size, default 4 (Options.Workers, R21)
    budget   time.Duration             // soft per-notification budget, default 200µs (R22)
    metrics  metrics                   // atomic counters, see Metrics()
    dispatch dispatchTable             // built once at New(), keyed by (arch, nr); immutable after (I8)
    guard    atomic.Pointer[modelGuard] // the models[] guard under no net: (R7); Run refreshes its addresses
}

// Options configures a Loop; every field has a spec-mandated default. Abridged: Log, Activity and the
// tier-2 recorder hooks KernelConnects, KernelFS and KernelNet (R7, R7a) are optional.
type Options struct {
    Workers int           // <=0 means DefaultWorkers, 4 (R21)
    Budget  time.Duration // <=0 means SoftCeiling, 200µs (R22)
}

// Sink is the pipeline entry point. Emit is called after the notification is answered (R23, I5) and may
// wait for room up to its lane's bound — the runtime's supervisor lane waits 250 ms, then drops and counts —
// never longer: the notification is never held, but the worker's next ones wait behind it.
type Sink interface{ Emit(ev *record.Event) }

// Policy is what New compiles into the table; immutable once handed over (I9).
type Policy struct {
    Rules       *agent.RuleTable // the compiled contract: net, unix, fs, exec entries
    Resolver    Resolver         // live IP sets and the resolv.conf endpoints (R8, R14); at run time a dns.Set
    RunID, Agent string
    Record      agent.RecordMode // overrides Rules.Record when set
    MaxArgvSize int              // <=0 means DefaultMaxArgv, 128 KiB (R3, R16)
    Observe     bool             // an observe run: every refusal is answered CONTINUE (R30)
    Cgroup      string           // the run's cgroup, for signals below Landlock ABI 6
}

// Resolver matches an inet destination against the net entries with their live IP sets, refreshed on TTL
// behind it with the stale addresses kept on a failed lookup (R8, R8a, R27).
type Resolver interface {
    Match(dst netip.AddrPort, proto string) *NetMatch // nil: no entry admits dst
    ResolverAddrs() []netip.AddrPort                  // empty: the R14 exception matches nothing (E32)
}

// notif is per-notification working state, allocated once per notification, never shared across workers.
type notif struct {
    id     uint64    // req.ID from NOTIF_RECV; the ID_VALID/SEND key
    pid    int       // req.Pid; advisory until bracketed by ID_VALID (E3)
    arch   uint32    // req.Data.Arch (AUDIT_ARCH_*)
    nr     int32     // req.Data.Nr
    args   [6]uint64 // req.Data.Args
    recvAt time.Time // monotonic (time.Now()), for held_ms (E14)
    answered, gone, detached, replaced, starved bool // I11, R19, E35/relayCancelled, R21 backfill
    entry  entry     // the dispatch row handling it
}

// handlerFunc decides and responds for one kind; owns the full recv→respond lifecycle for its id.
// Always invoked through the recover() wrapper in the worker loop (R25), never called directly.
type handlerFunc func(l *Loop, n *notif)

// entry is one dispatch row. A handler that panicked or never answered is refused with R10's errno whatever
// the row (failClosed, R25, I11).
type entry struct {
    name string
    fn   handlerFunc
}

// dispatchTable is per-GOARCH (x86-64 has legacy+*at syscalls, arm64 only *at forms); built once at New();
// an nr with no entry for the notified arch is refused ENOSYS (R1). The package is restricted to amd64/arm64
// by build tag (R26); no other GOARCH compiles.
type dispatchTable map[dispatchKey]entry
type dispatchKey struct{ arch uint32; nr int32 }

// resp is the three response shapes NOTIF_SEND can take (R18).
type resp struct {
    cont    bool  // SECCOMP_USER_NOTIF_FLAG_CONTINUE; error/val ignored by the kernel when set
    errno   int32 // negative errno; val forced to -1
    val     int64 // syscall return value on a relayed success
    refusal bool  // an errno this loop chose, not one a relayed syscall returned: the only answer an
                  // observe run turns into CONTINUE (R30); a relayed errno is a real result (I3)
}

// metrics are run-scoped counters read once at shutdown for run_end.supervisor (R24).
type metrics struct {
    notifications, anomalies, orphaned, starved, relayLimited atomic.Int64
    heldUS atomic.Int64 // sum not average, µs, monotonic-derived (E14); Metrics reports it in ms
}
type Metrics struct{ Notifications, HeldMS, Anomalies, Orphaned, Starved int64 } // snapshot from Loop.Metrics() (R24)
```

Additive fields on the `exec` record v1 payload (VERSIONING §2 permits optional additions within `v: 1`):
`argv_truncated bool`, set when the 128 KiB argv budget (R3, R16) is exceeded; `path_search bool`, set on a
candidate of the run's own `PATH` search (R28); `fileless bool`, set on an exec whose image is anonymous — a memfd,
another anonymous inode, or a file unlinked since it was opened (R16b); `dropped bool`, set on an exec whose
image, or in a run with command rules a `#!` interpreter or a directly-invoked loader's program it loads, lies under
a write entry and whose inode changed after the loop was built, before the agent ran — a binary the run wrote and
then executed (R16b). `script`/`stage` are not populated here (§11). These four keys
(`argv_truncated`, `path_search`, `fileless`, `dropped`) are additive optional v1 fields; their canonical home is
`docs/p0/record-ledger.md` §2.2 per `docs/VERSIONING.md`, which lists all four.

**Changes.**
- 2026-09-29: the type sketches restated from the code (`Sink` interface, `entry.decision`, `resp.refusal`,
  `heldUS`, the `Policy` the loop takes).

## 3. Repositories and storage

This package owns no durable storage. What it reads and holds:

| What | Where | Access | Lifetime | Concurrency |
|---|---|---|---|---|
| Notify fd | moved in at `New(listener *sys.FD, ...)`, originally `pidfd_getfd(child_pidfd, notify_fd)`; each ioctl and poll borrows the number for that call (ADR 0023) | `ioctl(2)`: `NOTIF_RECV`, `NOTIF_ID_VALID`, `NOTIF_SEND` | one per run; closed by `Loop.Run` shutdown (E24), never reopened | N workers call `NOTIF_RECV` concurrently on the same fd; the kernel serializes delivery, one notification per call |
| Target memory | `/proc/<pid>/mem` (fallback) or `process_vm_readv` (primary, no fd) | read-only, bounded (§5 R3) | per-notification; any `/proc/<pid>/mem` fd opened for a read is closed before the handler returns (E28) | one reader per notification; no cross-notification cache |
| `/proc/<pid>/fd/<n>`, `/proc/<pid>/cwd`, `/proc/<pid>/root` | `readlink(2)` (magic symlinks, single hop, E12) | read-only | per-notification, not cached | — |
| Target pidfd (for R9/R12 duplicates) | `pidfd_getfd(target_pidfd, sockfd, 0)`, `target_pidfd` itself obtained fresh per notification (E31) | one duplicate fd per decision, closed after use | per-notification, never cached | one acquire per notification; re-validated against `ID_VALID` immediately before use (E31) |
| `Policy` | in-memory only, compiled once by `New` into an immutable table (`atomic.Pointer[compiled]` on `Loop`) | never swapped: a destination's addresses live behind `Policy.Resolver`, the runtime's `dns.Set`, which its own TTL loop refreshes and which owns the R8a stale-`Nets` merge (R27); the `models[]` guard's are refreshed by `Run` | lives for the run | lock-free reads (`Load()`) |
| `Sink` channel | the supervisor lane of the runtime's event queue (buffered 4096), owned by `internal/runtime` | a send that waits for room up to the lane's bound (250 ms), then drops and counts (P0-DESIGN §2.4) | run-scoped | many producers, one drain goroutine |
| `metrics` | in-process atomics on `Loop` | read via `Metrics()` | run-scoped; read once at shutdown for `run_end` | lock-free increments from every worker |

Nothing here is a file this package creates or must survive a restart; on supervisor death the kernel's own
fail-closed behavior (every notified syscall returns `-ENOSYS` once the listener is unreferenced, ARCHITECTURE §6)
is the durability story, not a checkpoint.

**Changes.**
- 2026-09-29, `Policy` row: compiled once in `New` and never swapped; `Loop.UpdatePolicy` removed.
- 2026-09-29, `Sink` channel row: the supervisor lane waits up to 250 ms for room before it drops.
- 2026-10-19, Notify fd row (ADR 0023 C7): `New` takes the listener as a `*sys.FD` and owns it from the call on,
  closing it itself when it returns an error; the production kernel borrows the number per call, so a listener
  whose owner is closed under the loop is `waitInvalid` (the failure POLLNVAL reports), never a call on a reused
  number.

## 4. Functions and contracts

`func New(listener *sys.FD, pol *Policy, sink Sink, opts Options) (*Loop, error)` — Pre: `listener` owns a valid,
already-installed `NEW_LISTENER` fd, moved in by the caller (`launch.Child.WaitNotifyFD`, amended 2026-10-19, ADR 0023
C7): the Loop owns it on every path, and an error return has closed it; `pol != nil`. Post: `Loop` with defaults applied (`Workers`≤0→4, `Budget`≤0→200µs)
and dispatch table built for `runtime.GOARCH` (build-restricted to amd64/arm64, R26); no syscalls made yet. Not safe
to call twice on the same fd from two `Loop`s (both would race `NOTIF_RECV`).

`func (l *Loop) Run(ctx context.Context) error` — Pre: called at most once per `Loop`. Post: starts `Workers`
goroutines, each looping `NOTIF_RECV → dispatch (via the recover() wrapper, R25) → respond`; blocks until `ctx`
cancels, the listener hangs up (`POLLHUP`: the run's last task exited) or the fd errors; cancellation travels on an internal
wake pipe and `l.fd` is closed only after every worker has left (E24), so nothing closes it under a worker. Returns
`nil` on clean shutdown (a cancelled `ctx` or a hangup); wraps in `ErrListener` and returns any poll or `NOTIF_RECV`
failure other than `EINTR`/`ENOENT` while `ctx` is live, `EBADF`/`EINVAL`/`ECANCELED` and a `POLLNVAL` listener
included (a listener lost under a live run; `ENOTTY` is a programmer error), surfaced not swallowed. `POLLERR` alone on the
listener is neither: it is `seccomp_notify_poll`'s `mutex_lock_interruptible` on `notify_lock` failing for a signal
pending on the polling thread, and the worker polls again. Side effect: answers every
notification exactly once, or none if `ID_VALID`/`SEND` returned `ENOENT` first (R19). Not idempotent
(`ErrAlreadyRunning` on a second call). No internal timeout — `ctx` is the only stop signal short of the fd's owner
closing it first.

`func (l *Loop) Metrics() Metrics` — lock-free snapshot, safe concurrently with `Run`; called once after `Run`
returns (drained) to populate `run_end.supervisor`.

Per-handler contracts (unexported, `func(l *Loop, n *notif)`, one per dispatch entry, each run under the R25
recover() wrapper):
- `handleConnect` (TCP and unix): exactly one `NOTIF_SEND` — real `connect()`-on-duplicate result (R9) or
  `-EACCES` (R10, the errno of a connect this loop refuses, in every tier, SEMANTICS §5); exactly one `net` event, or none if the
  target died first (E1/E2, not an error); never returns an error, internal failures degrade to fail-closed (R5)
  plus `rule: args-unreadable`. The `target_pidfd` needed for
  the R9 duplicate is acquired fresh per notification and re-validated against `ID_VALID` immediately before use
  (E31), extending R2's bracketing to the pidfd-acquire step, not only memory/path reads. A unix connect is
  `relayUnix`: the trapping task's credentials and `O_PATH` root and cwd are read under the same bracket
  (`kernel.TaskOf`), and the connect is made by `kernel.ConnectUnixAs` on a thread holding those credentials, on
  the socket the path resolves to (R11); its `NOTIF_SEND` carries the real result, a walk's own errno, or `-EACCES`
  for a resolved socket nothing admits and for a connect it could not make as the task (`relay-credentials`).
- `handleSendTo`/`handleSendMsg`/`handleSendMMsg` (TCP Fast Open / UDP address-time): decides like connect for `SOCK_STREAM` (R12, block-capable;
  a stream socket that already has a peer is `CONTINUE`d, R13a, unless the send carries `MSG_FASTOPEN`) or
  best-effort for `SOCK_DGRAM` (R13b: a destination the policy refuses is refused, an admitted one `CONTINUE`d; an address it cannot match,
  an unrecognized family or `AF_UNSPEC`, is refused on every socket type, connected or not, R4 — under no `net:`
  section only `AF_UNSPEC`, R7, except on an IP socket under the `models[]` guard, where every one is, as under a
  `net:` section). Distinguishing socket type needs
  `getsockopt(SOL_SOCKET, SO_TYPE)` on a duplicate — the notification carries only the fd *number*, which is itself
  race-prone against fd reuse between trap and duplicate (E33).
- `handleExecve`: reads `argv` bounded 128 KiB / 8192 entries (R3, R16, E10, E11); answers by R16b — a granted exec
  `CONTINUE`d, a PATH-search candidate with its lookup's errno, anything else refused by this loop (with no `exec:`
  section, allowed unless a `deny_read` refuses its open); emits one
  `exec` event with `path`, `argv`, `argv_truncated`, `exec_id` (`<run>/<pid>/<start-boot-ns>`, RUN-IDENTITY.md;
  `start-boot-ns` computed from `/proc/<pid>/stat` field 22 `starttime`, which per `proc_pid_stat(5)` is expressed
  in **clock ticks**, not nanoseconds — converted as `starttime * 1e9 / sysconf(_SC_CLK_TCK)`; at a typical 100 Hz
  `CLK_TCK` this yields only ~10 ms resolution, coarser than the field name implies — see E3), `parent_exec_id` from
  the process cache by ppid (best-effort; `unattributed` for a re-parented orphan).
- `handleOpenAt`/`handleUnlinkAt`/`handleRenameAt`/`handleMkdirAt`/`handleSymlinkAt` (and the x86 `handleOpen`/`handleMkdir` forms): always `CONTINUE` (R15/R17); read
  path(s) with dirfd resolution (R6); emit one `fs` event with an advisory `verdict` from the compiled
  `write`/`deny_read` set (passed alongside `Policy` at `New`, not `Policy` itself, which holds only net rules).

Timeouts: no handler sets a deadline on any read or `connect()` (the duplicate inherits the target's own blocking
mode via the shared open file description, R9); the only time bound is the soft `budget` metric (R22), which never
aborts in-progress work. The relayed `connect()`/`sendto()` of R9/R12 is nevertheless performed on its own goroutine
rather than inline on the worker, and the handler waits for it against `Run`'s cancellation: the syscall keeps its
lack of a deadline, but it is no longer the thing `Run` is joined on. A run cancelled while a relay is in flight
abandons that notification unanswered — its real result will never be known and I3 forbids inventing one — and the
listener close that follows is what fails the trapped syscall closed with `-ENOSYS` (ARCHITECTURE §6). The relay
goroutine owns the duplicate from the moment it starts and closes it when the syscall returns, because closing it
underneath a live `connect()` would free the fd number while the kernel is still using it. On a 5.19+ kernel the
listener carries `WAIT_KILLABLE_RECV` (E35), so for that same undeadlined duration the target's non-fatal signals
wait as well; only a fatal one ends it.

Waiting for that goroutine is itself bounded twice, neither bound touching the syscall's own lack of a deadline.
After `relayGrace` (2 ms — an allowed connect to a local or already-established endpoint returns well inside it,
so the common path pays for neither) the handler backfills its worker with a standby and retires when it returns,
so a slow relay costs the pool nothing (R21); and from the same point it polls `NOTIF_ID_VALID` every `relayPoll`
(20 ms), because the target may abandon the syscall at any moment and the kernel does not say so (E35). The three
outcomes a handler can therefore see are: the real result (answered and recorded, I3); the run cancelled (nothing
answered, nothing recorded); and the notification gone (nothing answered, the launched syscall recorded with
`result_unknown`).

**Changes.**
- 2026-09-29: the per-handler contracts name the handlers the table has (`handleConnect`, `handleSendTo`/`handleSendMsg`/`handleSendMMsg`, `handleOpenAt` and the other `*At` forms); `handleUnixConnect`, `handleSendAddr` and `handleOpenWrite` never existed.
- 2026-09-29, `Run`: a listener lost under a live `ctx` (`POLLNVAL`, `EBADF`/`EINVAL`/`ECANCELED`) is `ErrListener`, not `nil`.
- 2026-09-29, `UpdatePolicy` removed: it had no caller; resolver freshness is `dns.Set`'s (R8, R27).
- 2026-10-16, `Run`: `POLLERR` alone on the listener is no hangup. The kernel answers it, and nothing else, when the
  poll's interruptible lock on `notify_lock` meets a signal pending on the polling thread (kernel/seccomp.c,
  `seccomp_notify_poll`, since 5.0); the Go runtime signals its threads all the time, and `RECV`, `SEND`, `ADDFD` and
  every notifying task contend for that lock. Read as a hangup, it ended each worker it reached as if the run were
  over, `Run` returned `nil` and closed the listener under a live agent, and every notified syscall of the agent then
  failed `ENOSYS` with no line and no error (`TestIntegrationApprovedOpensSurviveASignalStorm`: 2 of 12 alone at
  moderate host load, 6 of 60 with the guest throttled). Only `POLLHUP` is the hangup now; `POLLERR` alone is a wait
  that took nothing. *Rejected:* retrying inside `Wait` until the bit clears, which spins without releasing the
  receive mutex or reading the context should a kernel ever report it persistently.

## 5. Business rules

**R1 — dispatch scope.** `pidfd_getfd` is notified under ADR 0113 and refused `builtin.other_tty`: descriptor imports cannot bypass the terminal domain. `ioctl(TIOCGPTPEER)` is relayed from a pinned master and installed with ADDFD.

 A notification for a syscall the table has no entry for is answered `ENOSYS`, as the
kernel answers every notifying syscall once the listener is gone, never `CONTINUE`, which would make a refusal by
notification alone fail open on a missing or misnumbered entry. `TestEveryNotifiedSyscallHasAHandler`
(enforce/landlock) walks every filter variant on both arches and fails when a notified number has no entry
(`Dispatches`). The table holds `socket` and `socketpair` (x86-64 41/53, arm64 198/199): reached only for a triple
the filter's allowlist did not admit, answered `EPROTONOSUPPORT` (an inet type or protocol) or `EAFNOSUPPORT` (a
family) and recorded `refused` with reason `net-not-allowed`, rule `unmatched`, the triple in `target`; a decision
kind with no `CONTINUE` path (enforce-landlock E30). *Amended 2026-10-17 (ADR 0018 (7)):* it holds `setsockopt` too
(x86-64 54, arm64 208), reached only as `SOL_TCP`'s `TCP_ULP` under a `net:` section and answered `ENOENT` (what a
kernel without that ULP answers), whatever the name, and recorded `refused`, op `setsockopt`, target
`TCP_ULP "<name>"` with the name read from the agent's memory for the line alone (`record.SocketOption`; min(optlen,
15) bytes, `TCP_ULP (name unread)` when unreadable; bracketed by `ID_VALID` as R2 and I1 require, so a notification gone
before or across the read is neither answered nor recorded), reason `net-not-allowed`, rule `unmatched`; anything else
reaching it is refused `EPERM` with its numbers, a decision kind with no `CONTINUE` path (`handleSetsockopt`).
*Amended 2026-10-20 (R13's pending frames; enforce-landlock R11d):* in a run that decides datagrams
(`agent.RuleTable.DecidesDatagrams`: a `net:` section, a guarded `models[]` endpoint or a net gate) `setsockopt` is also
reached as `UDP_CORK` at `SOL_UDP` or `SOL_UDPLITE`, refused with R10's errno whatever the value and recorded
`refused`, op `setsockopt`, target `setsockopt level 17 option 1` (or level 136), reason `net-not-allowed`, rule
`datagram-corked` (`refuseCork`); the table holds `sendfile` and `splice` (x86-64 40/275, arm64 71/76), reached only in
such a run, a decision kind refused `datagram-corked` into a socket that can hold a UDP frame and continued into any
other descriptor (`spliceInto`); and `sendto` with no address is notified when its flags carry `MSG_MORE`. The filter answers `openat2`, `open_by_handle_at` and `io_uring_setup/enter/register`
directly with `SECCOMP_RET_ERRNO(ENOSYS)` at the BPF level (owned by `enforce/*`, not here); these, and any
non-native-arch call, never generate a notification. `Loop`'s table covers only `SECCOMP_RET_USER_NOTIF` actions, keyed
by `(arch, nr)`; `buildDispatchFor` is the table and `TestEveryNotifiedSyscallHasAHandler` holds it to the filter's
notify set. Each entry's number is its named syscall's in golang.org/x/sys's generated tables on both arches
(`TestDispatchNumbersAreTheKernels`, as `TestFilterNumbersAreTheKernels` holds the filter's), and two entries at one
number panic when the table is built, so a typo landing on another dispatched syscall fails loud. The network set:
`connect`, `bind`, `listen`, `sendto` (addr≠NULL, or `MSG_MORE` in a run that decides datagrams), and `sendmsg`/`sendmmsg` on **every** call — classic
BPF cannot dereference `msg_name` (enforce-landlock R11), so each costs a notification, connected sends included, and
this loop reads the header and `CONTINUE`s one with no address (R13a). The path set: `execve`/`execveat`,
`open`/`openat`/`creat` (write mask `0x243` = `O_WRONLY|O_RDWR|O_CREAT|O_TRUNC`), `unlink`/`unlinkat`, x86-64's `rmdir`
(recorded as `unlinkat(AT_REMOVEDIR)` is, `op: unlink`), `rename`/`renameat`/`renameat2`,
`mkdir`/`mkdirat`, `symlink`/`symlinkat`, `link`/`linkat`, `mknod`/`mknodat` (recorded as the open that creates the same
name, `op: open`, `O_CREAT|O_EXCL`, as tier 2's kernel record writes one), `truncate` and the mode-change family
`chmod`/`fchmod`/`fchmodat`/`fchmodat2` (R15c, R17), under an `fs.write` gate the attribute families beside it —
`setxattr`/`lsetxattr`/`fsetxattr`/`removexattr`/`lremovexattr`/`fremovexattr`/`setxattrat`/`removexattrat` and
`chown`/`lchown`/`fchown`/`fchownat` (R17) — and the mount family a Landlock domain refuses — `mount`,
`umount2`, `pivot_root`, `move_mount` (R31). The rest: `socket`/`socketpair` for a triple the filter's allowlist does
not admit (ADR 0018), `add_key`/`request_key`/`keyctl` (R32), the eleven System V IPC syscalls (R34), `unshare`/
`clone`/`setns` when the run must refuse them (enforce-cgroup-observe E24), and below Landlock ABI 6 `kill`/`tkill`/
`tgkill`/`rt_sigqueueinfo`/`rt_tgsigqueueinfo`, `fcntl` and `ioctl` (R33), and at every ABI `prlimit64`,
`setpriority`, `sched_setparam`/`sched_setscheduler`/`sched_setaffinity`/`sched_setattr` and `ioprio_set` when they
name another process (R35), and `inotify_add_watch`/`fanotify_mark` (x86-64 254/301, arm64 27/263) and `fcntl`'s
`F_NOTIFY` in every enforcing run (R36, *added 2026-11-02*). The numbers below are the network and
path sets'; the others are in the package's arch tables. x86-64 (`AUDIT_ARCH_X86_64`) has both legacy and
`*at` numbers: `connect`=42, `sendto`=44, `sendmsg`=46, `execve`=59, `rename`=82, `mkdir`=83, `rmdir`=84, `creat`=85, `unlink`=87,
`symlink`=88, `openat`=257, `mkdirat`=258, `unlinkat`=263, `renameat`=264, `symlinkat`=266, `sendmmsg`=307,
`renameat2`=316, `execveat`=322, `mknod`=133, `mknodat`=259, `pivot_root`=155, `mount`=165, `umount2`=166, `move_mount`=429. arm64
(`AUDIT_ARCH_AARCH64`, generic table) has only `*at` forms: `connect`=203,
`execve`=221, `sendto`=206, `sendmsg`=211, `sendmmsg`=269, `execveat`=281, `mkdirat`=34, `unlinkat`=35,
`symlinkat`=36, `linkat`=37, `mknodat`=33, `renameat`=38, `renameat2`=276, `openat`=56, `umount2`=39, `mount`=40, `pivot_root`=41,
`move_mount`=429 (no legacy `open`/`creat`/`mkdir`/`rmdir`/`unlink`/`rename`/
`symlink` exist on arm64; `openat2`=437 both arches and `open_by_handle_at`=304 (x86-64) / 265 (arm64), never
dispatched). x86-64's `rmdir`=84 is in the filter's notify set and this table, so glibc's `rmdir(3)`, Python's
`os.rmdir` and coreutils' `rmdir` leave a line in every tier and under `--observe`; `open_by_handle_at`, which
opens from a `struct file_handle` rather than a path, never reaches the kernel (enforce-landlock R10, R11).

**R2 — ID_VALID bracketing.** Every target-memory/path read is preceded by `SECCOMP_IOCTL_NOTIF_ID_VALID(id)` and
re-checked with another `ID_VALID(id)` immediately before the data is trusted (the read is not atomic with the
check). The same bracketing covers the `target_pidfd` acquire before an R9/R12 duplicate (E31). `NOTIF_SEND` itself
re-validates `id`. No handler, including record-only ones, skips the pre-read check — a stale `pid` can belong to a
reused process (E3). "Path read" includes the `readlink` of `/proc/<pid>/{cwd,fd/N}` that R6 resolves a relative
pathname against: it reads no target memory, but it is addressed by the same `pid` and carries the same recycling
hazard, so it is bracketed on both sides like every other read (E9b).

**R3 — bounded lengths.** `sockaddr`: fixed `sizeof(sockaddr_storage)`=128 bytes, clamped regardless of `addrlen`
(E4). The clamp bounds the read, not the answer: a relayed `connect`/`sendto` whose `addrlen` the kernel refuses
(past 128, or negative) and a relayed `sendmsg` with a negative `msg_namelen` are answered the kernel's own `EINVAL`
and not performed (R9, R12, I3). A relayed `connect`/`sendto`/`sendmsg` whose address read came up short of
`min(addrlen, 128)` bytes is answered the kernel's own `EFAULT` (the copy in `move_addr_to_kernel` faults) and not
performed either; the readable prefix still decides and records (E19). The same two answers, in the kernel's order
(length, then copy), hold for an ask-scoped `connect` before any prompt and for an allowed IP `bind`, whose family's
minimum length is checked only after the copy (amended 2026-10-05: both performed with the readable prefix). Paths: up to `PATH_MAX`+1=4097 bytes, NUL-scanned; no NUL found → malformed, stop scanning (E20). `argv`:
pointer array capped at 8192 entries (E11) before any string is read; string bytes capped at 128 KiB total; exceeding
either sets `argv_truncated: true` and stops collecting. These exact figures (8192, 128 KiB) are P0 engineering
defaults, not sourced to any required normative document (unlike `Workers`/`Budget`, which P0-DESIGN §2.7 sources
explicitly).

**R4 — sockaddr_storage.** Read the fixed 128-byte buffer, then branch on `ss_family`: `AF_INET` (16 B), `AF_INET6`
(28 B), `AF_UNIX` (up to 2+108=110 B, `sun_path` not necessarily NUL-terminated for abstract names). Unrecognized
family → `unmatched` → refused (E4). **`AF_UNSPEC` is the one carve-out and is not an unrecognized family**: in
`connect(2)` it is the defined, portable request to dissolve a socket's association, which the kernel routes
straight to the protocol's `disconnect` (`__inet_dgram_connect`, `__inet_stream_connect`). It names no destination,
sends nothing and can only narrow what the socket may reach, so there is nothing for R7 to match and refusing it
would refuse no destination. Under a `net:` section it is still **relayed on the duplicate, never `CONTINUE`d** (I2,
I3): `CONTINUE` would have the kernel re-read the sockaddr, which a sibling thread can rewrite into a real
destination between the decision and that read. Under a contract with **no** `net:` section it is `CONTINUE`d like
every connect there (R7): any destination a sibling could swap in is one that contract admits — except on an IP
socket under the `models[]` guard (R7), where a sibling could swap in the guarded endpoint, and on an IP socket while a
live `net` block exists (R7, *amended 2026-11-01*), where it could swap in the blocked one: both are relayed as
under a `net:` section. The event is `verdict: observed`, `rule: net.unspec`, `dst: unspec`, no `reason` — the same
reading R28 gives a `PATH`-search candidate, because nothing was decided and nothing was reached.
**The carve-out is `connect(2)`'s alone.** A send reads the same bytes as an address: `udp_sendmsg` and
`raw_sendmsg` accept `sin_family` `AF_UNSPEC` as a spelling of `AF_INET` and send to the `sockaddr_in` behind it,
`rawv6_sendmsg` reads a `sockaddr_in6` there, and `udpv6_sendmsg` reads "no address, use the peer". TCP alone
turns it away itself: `tcp_sendmsg_fastopen` answers an `AF_UNSPEC` address with `EOPNOTSUPP` before any connect
(measured on 6.17 with `net.ipv4.tcp_fastopen=1`: the same bytes with `sa_family = AF_INET` connect and send), and
a TCP send without `MSG_FASTOPEN` ignores the address. Which of those applies depends on the socket's domain, which
this tier never reads, so on `sendto`/`sendmsg`/`sendmmsg` an `AF_UNSPEC` address is an unrecognized family:
`unmatched`, refused with R10's errno, `dst: unspec`, even when the bytes behind the family word spell a declared
host — an agent that means that host spells it `AF_INET`. It is refused under a contract with **no** `net:` section
too, where every other family this tier does not parse is continued (R7): continued, the datagram reached any host
under a line that said `verdict: observed`, `dst: unspec`. The refusal is made whatever the socket is: `sendto`
and `sendmsg` refuse it on a datagram socket too (R13b's `CONTINUE` is for an address this tier matched and admitted) and on a
connected stream socket, and a `sendmmsg` batch in which any message the kernel would send carries one — any of
the first `UIO_MAXIOV` (1024), not only the first 64 — is refused whole, on every socket type (R13b). The
socket is still duplicated and its `SO_TYPE` read before the answer, only so the line's `proto` names the socket
the refusal was made on; the answer does not depend on it, and a socket that cannot be read makes the line
`rule: fd-raced` instead (§9).
**Deliberate costs of refusing whatever the socket is**, each a send the kernel would have completed without
reaching an undecided host, and each refused: `sendto`/`sendmsg`/`sendmmsg` without `MSG_FASTOPEN` carrying an
`AF_UNSPEC` or any other unrecognized address on a **connected TCP socket**, whose address the kernel ignores and
whose bytes go to the peer (measured on 6.17 for `AF_UNSPEC` and `AF_VSOCK`); and an `AF_UNSPEC` address on a
**connected IPv6 UDP socket**, which `udpv6_sendmsg` reads as "no address" and sends to the peer. The portable
spelling of either send is a `NULL` address, which is `CONTINUE`d as R13a's connected send.

**R5 — fail-closed on unreadable args.** An unreadable sockaddr/address (E18, zero-progress E19) makes the
connect/send decision `-EACCES, reason: net-not-allowed, rule: args-unreadable` (R10's errno) — never `CONTINUE`
outside an observe run (R30) — and so does a socket `pidfd_getfd` cannot duplicate (`rule: fd-raced`; `fd-unreadable`
for its `EPERM`, a non-dumpable target at tier 1, amended 2026-10-20). The exception
is a contract with no `net:` section and no `models[]` guard, which decides nothing (SEMANTICS §1, R7): there such a
connect or send is `CONTINUE`d and recorded `verdict: observed`, `best_effort`, under `args-unreadable`, `fd-raced` or `fd-unreadable`,
save an `AF_UNSPEC` send this loop did read, which is refused on every socket (R4, R7). An unprivileged tier 1 cannot
read a task that made itself non-dumpable (ssh-agent, gpg), and refusing its every connect restricted a network the
contract leaves open. Record-only ops (open/unlink/rename/mkdir/symlink) never fail this
way: `CONTINUE` regardless (Landlock enforces the real thing), event `path` empty with a parse-failure marker, and
`verdict: observed` whenever any pathname could not be named: one cut, one whose join to its dirfd is over `PATH_MAX`,
or a rename's or a link's second end, whose destination is then decided by no one here (tier 2 hands the recorder no
naming for it) — save
in a run whose built-in `deny_write` set is not empty, where a modification is a decision kind and one whose pathname
cannot be read whole is refused (R15c). An attribute change (the `chmod`, xattr and `chown` families) is recorded and
not refused there, so it stays record-only — save where a decision plane mode decides the
run (`Options.PlaneAttrs`): R17 refuses one beneath a `deny_write` target there.
A scored gate makes an fs action a decision kind for the kinds it scores: a write gate every
modification, attribute changes included; a read gate a read-open, an open that reads (`O_RDWR`; `O_RDONLY` with
`O_CREAT` or `O_TRUNC`), and the source of a rename or hard link, which it scores with its read predicates (gate.md
R1, 2026-10-16).
*Amended 2026-11-01:* all of that is about arguments this loop could not read, a thing an agent can do on purpose. A
fault of this loop's own is another matter: a handler that panicked, a handler that returned without answering and an
`ID_VALID` that failed are refused, every kind alike (`failClosed`), outside an observe run. The split that ran here,
where a record-only kind was continued unless a list of rules said otherwise, had no line for a held read (a panic
beneath `heldOpen` returned a `deny_read` nested in a write entry, or a nested `.env`, with exit 0 and one gap line:
Landlock had already said yes, ADR 0069 D6) or for a live block, and each new rule had to be added to it.

**R6 — relative paths via dirfd.** `AT_FDCWD` (-100) → `readlink("/proc/<pid>/cwd")`; any other `dirfd` →
`readlink("/proc/<pid>/fd/<dirfd>")` (E7). A `" (deleted)"`-suffixed target of an unlinked directory (link count 0)
marks the path unreliable rather than being concatenated verbatim (E8); a live directory whose own name ends that way
keeps its name. Either way the verdict is taken where the walk from the dirfd lands, never on the joined spelling (R15b's
spelling shortcuts and walk cache are skipped). `/proc/<pid>/root` is used only for display normalization across mount namespaces
(adopted containers); this package never opens anything inside the run — with one exception, R11's relayed unix
connect, which walks the socket's path `O_PATH` from the task's own `/proc/<tid>/{root,cwd}` on a thread holding
the task's credentials, follows no magic link, and neither reads nor writes what it opens.

**R7 — connect rule match.** `AF_INET`/`AF_INET6`: destination IP+port matched against `Policy.TCP` (or `.UDP` for a
connected datagram socket, R13a) in order; first `NetRule` whose `Nets` contains the IP and whose `Port` equals the
destination (or is 0, ICMP/raw) → `allow`, unless a refusing entry also covers the destination, which then decides
whatever the order (SEMANTICS §5); no match → `refused, reason: net-not-allowed, rule: unmatched` —
save that a host entry never admits an address its name resolved to that agent-contract R18 refuses: loopback and
the unspecified addresses, link-local and the cloud metadata endpoints, multicast, the machine's
`denied_resolved_addresses`, this host's own addresses, its interfaces' and, *since 2026-11-02*, every address of a
`local` route in its routing tables local, main and default, an AnyIP range's, as a live block and the `models[]` guard
read this host (a snapshot `admitResolved` takes over netlink and retakes once a second old, every host entry refused
while none was ever taken), and, for a name whose compile-time answer was public only (`NetRule.PublicAnswer`), the
private ranges; a localhost name keeps loopback and this host's
addresses. Such a match is refused `rule: net.denied_resolved[<entry>]`, `host` the entry's name, unless another
entry admits the destination on its own: a literal or CIDR entry naming it, a localhost name on loopback or on this
host's address, another host name whose own live answer holds it and whose own check allows it, or a grant the runtime
added; and a destination no entry matches that `Compile` dropped from an entry's answer (`NetRule.Denied`) is refused
under the same name, so a name the contract allowed that a refresh rebinds to `169.254.169.254` never reaches
the metadata service —
unless the contract has **no** `net:` section, which SEMANTICS §1 gives "deny nothing". Then this loop decides
nothing and performs nothing: every connect, and every Fast-Open send (R12), is answered `CONTINUE`, so the kernel
runs the agent's own syscall as the agent, and it is recorded `allow` with `best_effort`, `rule` naming the entry
that matches it (R14's resolver, the capture listener, a socket under a write directory) or `unmatched` — **one line
per connect**: while the run's kernel recorder reads this run (tier 2 under any record mode but `off`,
`Options.KernelConnects`), its `security_socket_connect` line records every continued `AF_INET`/`AF_INET6` connect
from the kernel's own copy of the address (enforce-cgroup-observe R5), and this loop writes no line for it. That line
names the connect as this loop's would have: the recorder asks this loop's own lookup (`Loop.ContinuedNet`, the
`decide` path a continued connect takes), so its `rule`, `host` and verdict are R14's resolver, the capture listener,
an entry the resolved-address check lets name it, or `unmatched`, always `allow`; the recorder's own matcher, which
holds neither R14 nor the runtime's entries, named a DNS query `unmatched` (`TestRecorderNamesAContinuedConnectAsTheSupervisor`,
`TestContinuedNetIsTheLoopsOwnLine`). This loop keeps its line for a connect
that hook does not record (unix, `AF_UNSPEC`, another family, an address longer than `sockaddr_storage`, which fails
before the hook, one shorter than its family's address, `addrlen` below `sizeof(struct sockaddr_in)` for `AF_INET` or
below `SIN6_LEN_RFC2133` (24) for `AF_INET6`, which the hook returns early for), and wherever
no recorder reads: tier 1, an observe run, a recorder not built, one that found no row
of its run or whose drain failed. The recorder's answer is asked after `CONTINUE` is sent, and waits only until the
runtime has started it (a cancelled run keeps this loop's line, unless the recorder was already decided), so no
connect has none, and none has two. The two lines spell a connect alike: `proto` is the socket's protocol as the
hook's `sk_protocol` names it (`protoOf` reads `SO_PROTOCOL`: a ping socket, SCTP and UDP-Lite are `raw`, MPTCP
`tcp`), and `dst` carries no IPv6 scope id, which the kernel's copy of the address does not keep
(`TestRecorderNamesAProtocolAsTheSupervisor`). The one exception is a `SOCK_RAW` socket opened with `IPPROTO_TCP`
or `IPPROTO_UDP`, `raw` here and `tcp`/`udp` in the hook, which reads no socket type. A sibling thread that
rewrites the family between this loop's read and the kernel's copy can move a connect out of the hook's families
unrecorded, the TOCTOU R30 accepts where nothing is enforced. A relayed or refused connect is this loop's alone.
*Amended 2026-11-01:* a live `net` block ends that reading on an IP socket. The reason to continue is that any address a
sibling swaps in after the check is one the contract admits, and a block refuses some of them, so while one exists,
in force or not (`Set.HasNet`), an admitted connect or Fast-Open send on an AF_INET or AF_INET6 socket (`SO_DOMAIN` of
the duplicate, an unreadable one taken as IP; `compiled.liveRelays`) is relayed on the copy the block was matched
against, whatever family that copy spells, as a net gate's is (ADR 0041 D6), and its line is this loop's and carries no
`best_effort`. A Fast-Open `sendmsg` with no address is relayed with none, and a stream batch, addressed or Fast-Open,
is refused `batch-send` (`compiled.decidesFastOpen`, R12, R13c), since a sibling can write an address in for the kernel's
read of either; both hold in the unix-only state (R7b) too. Before, a connect checked on a benign copy reached a server
on the block's exact destination in one try of five (`TestLiveBlockConnectRelayedRaceFree`,
`TestLiveBlockFastOpenRelayedRaceFree`, `TestLiveBlockRelaysAnAdmittedIPConnect`). A datagram stays R13b's, and a connect on
a socket of another domain stays the agent's own: GAPS C47. An
address of a family this tier does not parse goes the same way (R4's refusal exists because nothing can be
matched against it, and here nothing needs to be), and so do the sends the batch refusals exist for, because a
decision could not be made or carried out: R13b's batch carrying such an address, R13c's stream batch, R12's
ancillary data. **`AF_UNSPEC` in a send is the exception**: it is not
an address this tier merely cannot name — `udp_sendmsg` and `raw_sendmsg` send to the `sockaddr_in` behind the
family word — so continued, it would reach any host under a line recording `verdict: observed`, `dst: unspec`, and
`drift` and `measure` would never see where the bytes went. It is refused here as under a `net:` section (R4), and so
is a `sendmmsg` batch carrying one, which is read past any other unparsed family to find it; a `NULL` address
or `AF_INET` spells the same send. `connect(2)`'s own `AF_UNSPEC`, the disassociation, is still `CONTINUE`d and
recorded `observed`. R5's unreadable argument and a failed duplicate still refuse: they are this loop failing,
not a policy decision. The Landlock builder (`netRestricted`), tier 2 (it attaches no network program for such a contract,
`internal/runtime/enforce/cgroup`) and `decide.Evaluate` read the same contract bit, `agent.RuleTable.NetUnrestricted`
being the one this loop and `Evaluate` share; a table with no `Contract` fails closed, as the builder does. Under
`record: off`, where such a connect or addressed send writes no line, it is `CONTINUE`d from the address alone,
with no duplicate taken (`passesUnrecorded`); an address that refuses on every socket is still refused.
**Not relayed.** These connects are not relayed on the duplicate as declared ones are. A relay runs in this
process, which has no Landlock domain and at tier 2 runs as root, so it would connect the agent to an abstract name
its own domain's scope refuses (enforce-landlock R7; measured on 6.17 unprivileged, the scoped task's own connect
got `EPERM`, a relay of its socket succeeded and the listener read what the task wrote) and, as root, to a `0600`
root-owned socket its uid cannot open, the listener reading uid 0 in `SO_PEERCRED`. With no entry there is no
decision for R9's relay to protect from a swapped address, so the kernel's own checks are the ones that apply. One
of them is stricter than the contract and stays so on purpose: at ABI ≥ 6 the scope refuses an abstract name bound
outside the run. Neither this loop nor `Evaluate` can see the ABI or who bound a name, so both record the
contract's `allow` there: the kernel is stricter than the record says, never looser (agent-contract §11).
`RESOLVE_UNIX` is net:'s pathname-socket half, not a filesystem right, and the builder handles it only under a
`net:` section, at every ABI (enforce-landlock R6, R21), so the agent's own connect to a pathname socket outside a
write entry is allowed as this loop and `Evaluate` record it, and the scope is the only kernel check stricter than
"deny nothing". A connect this loop does decide — under a `net:` section, a declared unix entry included — is still
relayed, and a unix one is made as the task that trapped, with its credentials and on the socket its path resolves
to (R11). `AF_UNIX`: pathname resolved via R6 then compared to `Policy.Unix[].Path`; abstract compared as raw bytes
to `.Abstract` (E5). **R14 — resolver exception**: port 53 (UDP/TCP) to any `Policy.Resolver` address is always
`allow`, checked before the rule list, ungated by `net.allow` (SEMANTICS §5); an empty `Policy.Resolver` (E32)
means this exception matches nothing and DNS falls through to ordinary R7 matching.
**The `models[]` guard — direct model access stays behind capture.** Under `capture: forwarder`,
`agent.RuleTable.GuardedModels` applies with or without a `net:` section. Known model addresses and their local
aliases refuse connects, Fast-Open sends and datagrams with `reason: net-not-allowed`, `rule: models[host:port]`.
An explicit allowance cannot override that refusal; the synthetic `net.capture[...]` listener grant remains
reachable, and the launcher's upstream connection is outside the agent filter. Uprobe and off capture retain
normal network policy because direct connections are respectively captured or intentionally unrecorded.

Under a `net:` section, for a non-localhost model hostname, an unknown destination on the same port is refused as
`models.port[host:port]` unless an explicit `net.allow` entry safely admits it. A DNS answer known only to the
agent can no longer pass as unmatched. Unrelated HTTPS therefore needs an explicit allowance when a named model
uses port 443; other ports keep normal policy. *Amended 2026-10-05:* this reservation applied with
no `net:` section too (`compile` warned `model-port-restricted`, now removed), so such a run refused every other
HTTPS host. With no `net:` section (`netOpen`) `decideGuarded` again reserves no port, as before 2026-10-01: it
refuses the name's resolved addresses and the local aliases below, and every destination on its port `rule:
unresolved` until the name has resolved, and admits any other address `unmatched`. **Limit (a), under no `net:`:**
an address the agent's resolver returns and this process's lookup never did (another round-robin or geographic
answer) reaches the model, admitted `unmatched`; only a `net:` section refuses it. `TestModelEndpointByName` pins
the no-`net:` answer and `TestForwarderGuardWithExplicitNetworkPolicy` the `net:` one. Explicit destinations are deliberate trust grants, not remote-service identity
proof: a permitted proxy or endpoint that forwards traffic elsewhere remains the author's policy choice.
**Holding it.** The guard is a decision, so this loop holds it as it holds one under a `net:` section: on a socket
whose `SO_DOMAIN` is `AF_INET` or `AF_INET6` (one it cannot read counts as IP) every connect and Fast-Open send is
decided (`decideGuarded`) and an admitted one relayed on the duplicate (R9), not `CONTINUE`d, because the kernel
re-reads a continued address and a sibling thread could have made it the guarded endpoint's by then. As there,
`connect(2)`'s `AF_UNSPEC` is relayed (R4), and any other address that is not IP is refused (R4, E4) — a connect the
kernel would refuse on an IP socket anyway, so only the errno changes; R4 lists what refusing one in a send costs —
and so is a stream `sendmmsg` batch (R13c). Other IP destinations follow the policy above and retain their deciding rule, with no `best_effort`. A datagram (`sendto`, `sendmsg`)
whose address the guard refuses is refused with R10's errno and a refused line without `best_effort`, as R13b
refuses every datagram whose destination is refused (before 2026-10-16 this was the exception to R13b's "always
`CONTINUE`"): continued, it reached the model — QUIC over an unconnected socket sends
just this way — and at tier 2 too, where no `cgroup/sendmsg` program is attached for this contract. A datagram the
guard admits is not continued either: it is sent by this loop on the duplicate, to the
address it read and with the payload it read, as R12 relays a Fast-Open send, and answered with the real byte count
or errno, its line without `best_effort`. Continued, the kernel would read the address again after the decision,
and a sibling thread that rewrote it to the guarded endpoint in between (`127.0.0.1:P`, or `0.0.0.0:P`, which the
kernel sends to loopback) would deliver the datagram to the model under a line reading `allow`. A datagram is
relayed whole or not at all, so one this loop cannot reproduce exactly is refused: ancillary data (`rule:
ancillary-data` — a relay would send it with this process's credentials, and `SO_MARK` checks `CAP_NET_ADMIN`
against the sender), and a payload past 64 KiB or 1024 iovecs, or one that could not be read whole (`rule:
datagram-size`); a QUIC stack that sends with control messages (GSO segments, ECN) is refused under the guard for
that reason. A relayed send carrying `MSG_ZEROCOPY` is refused too, this one and R12's Fast-Open send alike,
addressed or not (`rule: zerocopy`): on a socket with `SO_ZEROCOPY` the kernel pins the pages it is given and may
transmit from them after the call returns, and in a relay those are this process's heap, whose next use could leave
for a peer the agent chose, while the completion that frees them goes to the target's error queue, which this
process never reads. Stripping the flag would send a copy but leave the target waiting for a completion the kernel
never makes (I3). The flag is refused whether or not `SO_ZEROCOPY` is set, since a sibling could set it between a
read of it and the relay; without it the kernel ignores the flag, so only a program that passes it for nothing
loses a send. Every `sendmmsg` batch on a guarded IP socket that carries an address is refused whole, datagram or
stream, its lines as R13c's (the model endpoint's message named by its rule, `rule: batch-send` on an admitted
one), since a batch cannot be relayed and continued it has the same rewrite race. A socket of any other domain
cannot reach an IP destination and is left to the kernel as before.
**Matching.** A literal address matches as written, IPv4-mapped or not (`agent.GuardAddrMatches`), and a loopback
endpoint stands for all of this host's loopback: 127.0.0.0/8, `::1` and the unspecified addresses `0.0.0.0`, `::`
and `::ffff:0.0.0.0`, on its port. The unspecified addresses match every guarded endpoint on their port, loopback or
not, because such a connect never leaves the host: from a socket bound to one of this host's other addresses the
kernel sends it to that address, so it reached an endpoint declared there. The kernel sends a connection to the
unspecified address to loopback (`ip_route_output_key_hash_rcu` turns daddr 0 into 127.0.0.1 or the socket's bound
source; `tcp_v6_connect` and `udpv6_sendmsg` turn `::` into `::1`), and a server bound to all interfaces answers on
every loopback address; so `connect(0.0.0.0:P)` — the URL vLLM and its like print — reaches a server on
127.0.0.1:P. Refusing them all costs at most another local server on the model's own port. A `localhost` name, or
one under `.localhost`, is loopback without a lookup (RFC 6761 §6.3). Any other host name matches the addresses
this process resolves it to — the one lookup this package makes, since no component resolved a `models[]` host into
the table — once before the loop is built, bounded by the DNS timeout, and again on TTL for the run (`modelGuard`,
refreshed by `Run`); a failed lookup keeps what the name had (R8a), and a successful one adds to it: the guard
refuses every address the name resolved to during the run, since the agent can still hold one a later answer
dropped. Until a name has resolved, every destination on its port is refused `rule: unresolved`, since any of them
could be it. `decide.Evaluate` applies the same named-port rule without DNS (under a `net:` section only; with
none it answers `refused`/`unresolved` for a literal on the port and `allow` for another name, amended
2026-10-05); exact model names and literal
addresses remain refused even when explicitly allowed. An explicit unrelated name or IP may be admitted by pure
evaluation but refused at runtime when DNS or interface membership identifies it as a known model alias.

Local endpoints (loopback, localhost, or a host-assigned address) guard all loopback, unspecified and assigned
host addresses. Each model-locality decision takes one fresh `net.InterfaceAddrs` enumeration for both endpoint
and destination, independent of the ordinary resolved-address cache's age. Enumeration failure is unknown and
fails closed even after an earlier successful snapshot. New LAN/bridge aliases therefore do not get the previous
one-second admission window. Locality is retained once an endpoint has been seen local during initial resolution,
refresh or a decision; removing its LAN address cannot reopen loopback or other host aliases. Pure evaluation cannot enumerate host interfaces and conservatively reports
`unresolved` for an unallowed literal it cannot classify on a local/literal model port. *Amended 2026-11-02 (GAPS
C46):* the enumeration is of this host's own addresses as a live block and a `net to` gate rule read them
(`pkg/policy/thishost`, OPERATIONS "Live blocks"): with the interfaces' addresses it reads the `local` routes of the
kernel's routing tables its default policy rules look up, local, main and default (`ip route show table local`;
unprivileged `RTM_GETROUTE` dumps), and every address of one is a host-assigned address, so an address of an AnyIP
range (`ip route add local 198.51.100.0/24 dev lo`) is guarded by a local endpoint, and an endpoint declared on one is
local. Read from the interfaces alone, `connect(198.51.100.7:8443)` reached a model server bound to all interfaces,
admitted `unmatched` under `models[127.0.0.1:8443]`, while a block on `127.0.0.1:8443` refused it. Tables that cannot
be read are unknown, as a failed enumeration is (`TestModelGuardReadsTheLocalTable`,
`TestThisHostReadsTheSameToTheGuardAndABlock`).

**Limits — explicitly trusted routes and syscall coverage.** A model is not identified beyond declared endpoints
and their guarded ports. Any explicitly reachable proxy, tunnel or second listener that forwards to the model
remains a trusted route. Guarded IP datagrams sent with `sendto` or `sendmsg` are relayed from immutable copies,
including a `sendmsg` with no destination. Addressed `sendmmsg` batches are refused. An unaddressed batch on a
guarded IP datagram, raw or seqpacket socket returns `ENOSYS` and records an enforced `batch-send` refusal:
callers must use individual supervised sends. Guarded launches append `single-request` to `RES_OPTIONS`
for glibc DNS, preserving existing resolver options; modern glibc does not itself fall back from `ENOSYS`. So do
launches whose gate scores `net` actions, whatever their capture mode, since a network gate refuses the same
batches ([gate.md](gate.md) R4; amended 2026-10-05). The mutable-header gap is
closed without writing per-message results into the target. Ordinary stream batches and non-IP sockets keep
their existing handling; E33 describes the separate descriptor-reuse boundary.
An explicit `net:` section additionally refuses every unlisted destination; any permitted intermediary or alternate
service port remains part of the contract's trust boundary.
**Tier 2:** its network programs refuse on a miss and have no default-allow row (`bpf/cgroup_net.bpf.c`), so for a
contract with no `net:` section they stay detached and this loop's guard is the tier's verdict, relayed connects and
refused datagrams included, as at tier 1. `TestModelEndpointIsRefusedWithNoNetSection`,
`TestModelEndpointSendsWithNoNetSection`, `TestModelEndpointByName`, `TestModelGuardKeepsEveryAddressANameResolvedTo`,
`TestModelGuardByLocalhostName`, `TestModelGuardResolvesOnTheRunRefresher` and
`TestModelGuardInAnObserveRun` pin it here, `TestIntegrationModelGuard` on the real kernel (0.0.0.0, its v4-mapped
form, 127.0.0.2 and UDP against a stand-in on 127.0.0.1), `TestEvaluateRefusesAModelEndpointWithNoNetSection` in
`pkg/spec/agent`, and kt2's forwarder half end to end (tier landlock on the host, tier cgroup as root in the guest).

**R7a — one line per action at tier 2.** At tier 2 three producers see a run's filesystem and exec actions: this
loop (the tier-1 filter the run inherits), the kernel recorder (its fexit programs on the `security_` functions,
with the LSM chain's return, enforce-cgroup-observe R9; `sched_process_exec`) and the fanotify listener. Each action
has one line, from the producer that holds its verdict (ADR 0016 (4), step 3):
- *The recorder's*, with the chain's verdict, for every fs action its hooks see — an open or create, unlink, rmdir,
  mkdir, rename, link, symlink, truncate — that this loop continues while a recorder reads the run
  (`Options.KernelFS`, the runtime's answer, as `KernelConnects` is for connects, under every record mode, since the
  recorder keeps refusals under `off`). This loop writes no line for it and hands the recorder its own naming
  instead, before it answers (`Loop.ContinuedFS`: the spellings, rule, verdict and reason, taken where the path lands
  and at both ends, keyed by the thread and stamped before the answer, checked by the operation and each end's
  final component where it lands: a thread makes one syscall at a time and a continued one reaches its hook only
  after the answer, so the action a record is of is its thread's last one handed over before the record's own
  `bpf_ktime_get_ns` stamp, however far the recorder has fallen behind), which the recorder uses for a record its
  directory index cannot name (an operation in a directory no entry is, a rename's or a link's other end): the chain's return stays the verdict and this loop's verdict is the model that explains a
  refusal. The recorder names an allowed modification by the entry that granted it, as `compile --test` does.
- *This loop's* for what it answers itself — R15c's and R15d's refusals, the fallback's mutation refusals at tier 2
  with no plane mode (R15's 2026-10-17 amendment, `fallbackMutation`) and R5's fail-closed ones, which never
  reach the kernel — for a mode change, which no hook of the recorder sees, for an `O_PATH` open, which reaches
  neither the recorder's `security_file_open` nor the listener (*amended 2026-10-25*: it was handed
  over and lost; it now leaves a tombstone in its thread's naming, as a refusal does), for every exec (R16b: it decides each
  on the image it resolves and names the grant, where `sched_process_exec` carries no verdict of a mechanism and
  names the spelling; the recorder writes no exec line, `observe.Options.SupervisorExecs`), and for every action
  while no recorder reads the run (tier 1, an observe run, a recorder not built or not reading), as at tier 1.
- *The listener's* for an open it refuses after the Landlock ruleset let it through (a read under a `deny_read` the
  ruleset leaves unenforced or an exec grant reopens, a write-open under a `deny_read` nested in a write entry):
  this loop writes none (a `mknod`, recorded as an open, is none: the listener never sees it, so it is decided as
  the create it is, `decide.OpMknod`, and keeps this loop's line) (asked of `decide.Evaluate`'s Landlock column where the path lands), and the recorder drops
  its own by the listener's rule (`decide.ListenerOpenRefused`) unless the chain returned Landlock's `EACCES`, which
  comes before the listener is asked, or the mount was never marked (enforce-cgroup-observe E24, then `observed`).
An exec the listener refuses by its image's open is this loop's line (R16b names it refused under the `deny_read`):
the listener asks `Loop.ExecLine` with the opener's thread and the image's device and inode, and writes none for
that open (`enforce.SupervisorExecLines`). The group requests `FAN_REPORT_TID`, so a sibling thread's open of the
same image cannot consume the exec's entry. A continued IP connect is the recorder's
line (R7). Residuals: an fs action that fails before the kernel's hook
(a missing name without `O_CREAT`) has no line, since nothing decided it; a record of a syscall the filter does not
notify (`mknod(2)`, `ftruncate(2)`) with the operation and final name of its thread's last handed-over action is
named by that action. `TestKernelRecordOwnsTheContinuedFSLine`, `TestContinuedFSIsKeyedByTheRecordsStamp`,
`TestContinuedFSUnderConcurrentThreads`, `TestTier2ExecUnderAListenerDenyReadIsRefused`, cgroup's
`TestListenerLeavesAnExecsRefusedOpenToTheSupervisor`, `TestTier2ListenerRefusalIsTheListenersLine`, observe's `TestOneLinePerActionWithTheSupervisor` and ADR 0017's
conformance cells at tier `cgroup` hold it.
*Amended 2026-09-29 (TIER3-PLAN T9):* where the kernel decision plane decides the run's execs (tier bpflsm, or tier
cgroup with a plane mode, and a contract with an `exec:` section: `enforce.DecisionPlaneReporter`) and a recorder
reads the run (`Options.KernelExecs`), an exec this loop allows and continues is the kernel's line, not this loop's:
the plane decides it again in `bprm_check`, race-free on the image the kernel loads, so this loop's allow is a
prediction the plane may overturn (the image swapped after this loop resolved it, a fail-closed walk, an identity
that no longer matches). The plane's own sample is the line of an exec it refuses, and the recorder's
`sched_process_exec` record, named by the plane's rule (`observe.Options.SupervisorExecs` false), the line of one it
allows. This loop keeps the lines of the execs it refuses or answers itself (R16b, R28) and the MCP server line of an
allowed exec. Residual: an exec this loop continued that the kernel fails outside the plane (`ENOEXEC`, `ETXTBSY`) has
no exec line, and an image open Landlock or the plane refuses is that open's fs line.
`TestExecContinuedIsTheKernelsLineUnderThePlane`, runtime's `TestKernelRecorderOwnsExecsUnderThePlane` and observe's
`TestIntegrationPlaneRefusalIsOneLine` hold it.
*Amended 2026-10-19:* that kernel line takes this loop's naming of the exec whether or not
the exec outcome links attach. Where they do not (RHEL 9's 5.14: no fast handover), this loop still decides the
exec and hands the recorder its naming (the spelling, argv, `fileless`, `dropped`) through the attempt
hand-over, and the recorder's `sched_process_exec` line joins it as the outcome-linked line does. It had handed only
a supervisor-owned marker there, so an allowed memfd exec read `/proc/self/fd/4` with no `fileless`: the record of
an anonymous image could not be told from an ordinary file's by descriptor. With or without the links, the attempt a
record joins is that exec's own: the hand-over gives the thread's latest attempt before the record, and every exec
this loop traps puts its attempt there before it is answered (a foreign-arch or x32 exec is refused by the filter and
traps none). So a supervisor-owned attempt the record joins means this loop wrote that exec's line, after the
recorder stopped reading, and the kernel's record is dropped, as on the linked path; an exec with no attempt is
counted `exec-metadata-missing` as the linked line's is. *Amended again 2026-10-19:* the
first text kept the kernel's line beside a supervisor-owned attempt, reasoning that a failed attempt stays in the
hand-over; it cannot be the one a later success joins, and an exec decided after a recorder failure got a second
line from the final drain. Rejected: keeping this loop's
own line where the links are absent, which is the prediction the plane may overturn (an allow line for an exec
the plane then refuses). `TestPlaneExecWithoutOutcomeLinksHandsItsNaming`, observe's
`TestPlaneExecWithoutOutcomeLinksJoinsNaming` and ADR 0017's `execanon/memfd-exec` on the rhel-9 row hold it.
*Amended 2026-10-16 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) Stage B, D5):* a held open (`gate.completion: held`, heldOpen) is answered by
this loop with `ADDFD|SEND`, never continued, so its one line is this loop's, whatever the tier. The open itself is
the run's open deputy's, and the kernel recorder drops every record of the deputy (`observe.Recorder.SetSkipProcess`,
set once the deputy said hello; `TestRecorderDropsEveryRecordOfTheDeputy`), the plane's refusal of one of its opens
included. The deputy is named by its pid and its start time, read from /proc right after its hello: the agent can end
the deputy, and a record of a later process given its pid is kept (`TestRecorderKeepsARecordOfTheDeputysPidFromAnotherProcess`). The run's reaper also leaves the deputy's zombie unreaped until the run reaps it at its end
(`launch.Child.KeepUnreaped`, `TestIntegrationKilledDeputyKeepsItsPid`), so no later process of the run is given that
pid at all; a launcher in a time namespace with a boottime offset reads a start that never matches, and the deputy's
records are then written beside this loop's lines, a second line and never a lost one. At a root tier the deputy opens only after this loop's checks (no read-only open ahead of them, as at tier
landlock). An errno the deputy's open meets is the task's answer and the line's `syscall_ret`, and its verdict follows
the recorder's rule for a refusal the kernel returned (ADR 0016 (1), (3), `decide.ChainFS`): an `EACCES`, `EPERM` or
`EXDEV` the tier's model explains (`decide.Evaluate` at the run's tier: the plane's or the listener's reading of the
contract) is that mechanism's refusal, written refused with the model's rule and reason; any other errno keeps the
floor's verdict, so an `EACCES` from the file's own permission bits or a host LSM names no contract refusal
(`TestHeldOpenKernelErrnoIsTheResultNotARefusal`). Where a decision plane decides the run (`Options.PlaneAttrs`), the
model also reads the opened object's identity: the plane keys some regular files at their own inodes (a deny_write
target, a linked file, `RuleTable.DenyWriteLinked`, an fs entry), so its refusal of a hard link to one made before
the run, whose own path the model allows, is explained by the model's answer at the path it keys the file at
(`planeKeyedAt`; amended 2026-10-25, GAPS C38, `TestHeldOpenKernelErrnoExplainedByIdentity`). A fanotify listener's refusal of a held open writes its own line,
not the recorder's, so where the listener refuses what this loop's floor allowed (a model divergence), its line stands
beside this loop's, a residual. *Amended 2026-11-04 (SEC08, ADR 0041 D2):* before a held file open acquires a descriptor,
compare fresh trapping **TID**/actual-opener authority facts under `ID_VALID` before and after the reads.
AppArmor current-string equality authorizes only from a reader whose policy-namespace depth is proven zero;
otherwise invisible ancestor stack components can differ. Missing, malformed or nonzero depth refuses by default.
The explicit top-level contract key `fs.apparmor_assume_root_namespace: true` (default false) permits an
administrator assertion only for unreadable depth, accepting hidden-ancestor risk. It never overrides known
nonzero/malformed depth, unreadable/different labels, unknown active modules, or SELinux/Smack facts. The
canonical contract hashes the opt-in; compile warns and `run_start.best_effort` always lists
`apparmor/assumed-root-namespace` when enabled, whether or not an open needed the assertion.
SELinux requires equal complete `attr/current` contexts and, for potential file creation (`O_CREAT`/`O_TMPFILE`),
equal readable `attr/fscreate` (successful empty reads mean policy defaults). Key and socket creation attributes
are outside this file-open operation. Smack completions all refuse: its current label omits per-process rules,
and there is no cross-task query to establish their equivalence. Generic attributes require SELinux to be the
sole task-label LSM. A complete module set comes from `lsm_list_modules(2)` (6.8+) or securityfs, never inferred
from CONFIG-dependent proc directories or one readable label. Unknown modules or unavailable facts refuse.
A known difference returns `EACCES`, `held-label-differs`, reason `fs-gate`; missing authority facts return
`held-label-unavailable`. The check precedes the overlapped read-only pin/open and every later destructive
open; supervisor-completed approvals and alternates compare against the supervisor. Approval does not bypass this authority check or its explicit administrator assumption.
The deputy cannot change labels or creation attributes under its filter, and the supervisor does not change them.
Masking only the securityfs list can work through the syscall; missing AppArmor namespace-depth visibility
still refuses matching visible labels by default; the warning names unreadable namespace depth, `EACCES` /
`held-label-unavailable`, readable securityfs from the root policy namespace as the fix, and the administrator
opt-in with its residual. No helper adopts another label, no policy equivalence is established,
and no guarantee about network relays or non-open operations is added. No task label is cached. Fresh reads
supersede Stage B's zero-task-/proc-read budget; the old timings are historical.

**R7b — the unix-only state (ADR 0070).** A contract with no `net:` section and no `host_sockets: true`
(`RuleTable.HostSocketsRefused`, `compiled.hostSockets`) admits every IP destination, but no connect is answered
`CONTINUE`: an IP one is relayed on the duplicate with the copied address (R9), and a unix one is decided
(`decideHostSocket`) and, admitted, relayed as the task (R11): a name a runtime unix: grant names by it, a pathname
under a write entry only when R11a's `boundByRun` says the run bound the socket it reaches, an abstract name only
when one of the run's own sockets holds it now (`runSockets.holdsAbstract`: the socket objects a task of the run called
`bind` on with an abstract name, `recordRunAbstract`, at most `abstractMax`, each asked of the kernel by its identity,
UNIX_DIAG_NAME; a failed lookup refuses `unix-origin-unread`), and every other one refused `host-sockets`
(`hostSocketsRule` renames `unmatched` and `unix-foreign` so). Residual of the abstract admit: the run's socket may
close between that answer and the relayed call and a process outside the run bind the freed name in between; from
ABI 6 the abstract scope refuses the agent's own connect to such a name, not the relay's. A
notification whose address or socket could not be read is refused (`passesUnresolved` is false). An addressed
datagram is decided the same way (`decideUnix` lands it, `decideLanded`), and an admitted one is relayed on the
duplicate from the copies read (`relayUnixOnly`, *amended 2026-10-24, part 2*): a unix-spelled copy as the task, to the
inode its name resolves to (`relayUnixDatagram`, `SendUnixAs`: R11's walk and admit with a send in place of the
connect; the receiver reads the task's uid and gid in `SCM_CREDENTIALS` and the supervisor's pid, which no unprivileged
sender sets to another's), and any other with the copied bytes (`relaySend`), which the kernel refuses on a socket of
another domain. A Fast-Open send and a send on a stream socket without a peer are decided like a connect (R12) and
relayed on the duplicate. An addressed send without `MSG_FASTOPEN` on a connected stream or seqpacket socket names
nothing the kernel reads, so its address is neither decided nor recorded (R13a); only the descriptor, which the kernel
looks up again after a `CONTINUE`, is guarded (`sendConnectedUnixOnly`, keyed on the duplicate's own domain and type):
a unix stream send is made on the duplicate with the copied address and no ancillary data, and the kernel's `EISCONN`
is the answer; an IP stream send goes to the peer on the duplicate with no address (`relayToPeer`, as `sendUnaddressed`
relays) where the relay reproduces it exactly, and is continued otherwise rather than cut at `sendBytes`; a seqpacket
send is continued, so its receiver reads the sender's own pid in `SCM_CREDENTIALS` (*amended 2026-10-25* and 2). A connect or send on a socket whose domain is neither IP nor unix is refused `host-sockets`
(`hostSocketRelayable`), save a route query (`routeQuery`: an addressed send without ancillary data on a
`NETLINK_ROUTE` socket to the kernel, `nl_pid` 0 and no group), which is relayed on the duplicate from the copies as
the task (`relayRouteQuery`, `SendToRawAs`) and recorded allow, rule `route-query`, so interface enumeration works. *Amended 2026-11-01 (ADR 0128):* the same holds under a `net:` section, where a netlink address is otherwise
undecidable and refused unmatched (`resolveTarget`, `decidesNetlink`), and in both states the relay reads what it sends:
`routeReadOnly` walks the copy as `netlink_rcv_skb` does and admits only rtnetlink's GET kind, and anything else is refused
`route-change` and never sent. Under a listener policy `bindRoute` makes a bind of a `NETLINK_ROUTE` socket with no group on the
duplicate. A connect on such a socket and a `sendmmsg` keep their refusals. A datagram the relay cannot reproduce exactly (I3: ancillary data, `MSG_ZEROCOPY`,
`MSG_MORE` or a corked socket, a payload past `sendBytes` or `msgIovs` or one not read whole) is continued with a
best-effort line, as are an unaddressed `sendmsg` and a `sendmmsg` batch (R13b), and an addressed send on a connected
seqpacket socket is continued with none (R13a): run_start lists `host_sockets/datagram` at tier landlock,
the residual that a sibling which writes a host socket's name into the agent's memory and `dup2`s a unix datagram
socket onto the descriptor reaches a datagram receiver (the journal, syslog) where Landlock does not refuse it, below
ABI 9 for a pathname (RESOLVE_UNIX) and below ABI 6 for an abstract name (the scope). The agent chooses the shape of its
calls, so it can always choose a continued one. No stream daemon is reachable so:
the kernel refuses a datagram to a stream or seqpacket socket. At tiers cgroup and bpflsm the rule holds unchanged,
since a decision plane leaves connect, `sendto` and `sendmsg` notified (it narrows only the fs notifications,
enforce-plane R27), but no kernel program of the run decides a unix destination for such a contract: run_start lists
`host_sockets/root-tier` in `host_sockets/datagram`'s place, best effort until the root tiers carry a kernel program for it (*amended
2026-10-25*). Tests: `TestConnectInTheUnixOnlyState`, `TestDatagramInTheUnixOnlyState`, `TestIntegrationUnixOnlyState`,
`TestIntegrationUnixOnlyRaceFree` (10,000 tries, 0 foreign connects), the conformance table `hostsock.yaml` (KVM 6.17:
every root axis refused `host-sockets` by the supervisor).

**R8 — TTL refresh.** Each `NetRule.Host` is re-resolved on TTL behind `Policy.Resolver` — the runtime's `dns.Set`,
driven by the runtime's own refresh loop — and matched through it per notification; the loop's table is compiled
once, in `New`, and never swapped. **R8a**: a resolution failure keeps the stale `Nets` (never empties it); only a
successful re-resolution replaces it (E29). **R27** assigns ownership of this merge to `dns.Set`, not to `Loop`.

**R9 — connect on duplicate.** For an allowed TCP/unix connect: `pidfd_getfd(target_pidfd, sockfd, 0)` duplicates the socket (same open file description, so `O_NONBLOCK` and other `fcntl` state carry over; the `target_pidfd` is acquired and re-validated per E31); `connect(dup, sockaddr, addrlen)` with the read sockaddr — for a unix one, as R11 says: as the task that trapped, to the socket its path resolves to; the *real* result becomes the response — `error=0,val=0` on success, `error=-EINPROGRESS` pending, or the real errno (`ECONNREFUSED`, `ENETUNREACH`, `ETIMEDOUT`, …) — never fabricated (I3). `CONTINUE` is never used for a connect (ARCHITECTURE §7, I2), except for a refusal in an observe run (R30), where an allowed connect is relayed too, and for every connect under a contract with no `net:` section, which decides none (R7) — save a connect on an IP
socket under the `models[]` guard, which is decided and relayed (R7). *Amended 2026-10-05 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) D6):* and save a connect a network gate ([gate.md](gate.md) R4) admits on a socket whose `SO_DOMAIN` is IP or unreadable, which is relayed with the copied bytes whatever family they spell, so the gate's score holds against a sibling's rewrite; a source-routed socket is refused (`relay-source-routed`). R12's Fast-Open send and R13b's addressed IP datagram follow the same rule under a network gate (`TestGateRelayKeysOnSocketDomain`, `TestGateRelayRefusesSourceRoute`). *Amended 2026-10-05 ([enforce-landlock](enforce-landlock.md) R11b):* the source-route refusal is two halves. This loop's `IP_OPTIONS`/`IPV6_RTHDR` read on the duplicate is a snapshot of a socket the agent's threads share, so alone it was check-then-act: a sibling's `setsockopt` between the read and the relayed call added a route the read never saw. Under a network gate the filter now refuses that `setsockopt` (`IP_OPTIONS`, `IPV6_RTHDR`, `IPV6_2292RTHDR`, `IPV6_2292PKTOPTIONS`) with `EPERM` on its scalar arguments, so no thread of the run can add a route, and the read decides a socket that carried one before the filter applied. A process outside the run that shares the socket can still set one at any time; that is a disclosed residual ([gate.md](gate.md) R4), not a refusal. *Amended 2026-11-02 (GAPS C34):* both halves hold under every `net:` section too, not only under a network gate. With a `net:` section and no gate an allowed IP connect is relayed (above), and the relay connected with whatever source route the socket carried, so the SYN went to the route's first hop, an address no entry admits; the filter now refuses the `setsockopt` that sets a route there as well (enforce-landlock R11b), and the options read on the duplicate is made before every relay on a socket whose `SO_DOMAIN` is IP or unreadable, refusing a routed or unreadable one `relay-source-routed` (R12's Fast-Open send and R13d's approved datagram likewise). A socket of another domain carries no IP route and is not read. Under the `models[]` guard with no `net:` section the read is not made: that contract admits every destination but the guarded endpoint (`TestNetSectionRelayRefusesSourceRoute`, `TestNetSectionAskedDatagramRefusesSourceRoute`).

**R10 — EACCES with reason.** Undeclared host/port: no `connect()` attempted; `error=-EACCES,val=-1`; event `net verdict=refused reason=net-not-allowed rule=<matched-or-"unmatched">`. `-EACCES` is the errno of a connect this loop refuses, in every tier (spec/policy/SEMANTICS.md §5, "The errno of a refusal"): it is what Landlock's own TCP backstop returns, so a refusal reads the same however it was reached, and at tier 2 this loop still decides first, so the agent meets it there too; tier 2's kernel program refuses only what this loop relayed, with the kernel's `EPERM`, returned as the relay's real result (R9, I3). It is never `ECONNREFUSED`, which is a real peer's answer and is recorded `allow` when a relay returns it. R18(b), I2 and the `handleConnect`/`relayUnix` contract (§4) use the same errno. *Settled 2026-09-23:* this rule used to carry the errno as an unresolved conflict (§11): docs/ARCHITECTURE.md §7 said `-ECONNREFUSED` and spec/reason/REASON-CHANNEL.md §1 `-EPERM`, against `-EACCES` in SEMANTICS §5 and docs/P0-DESIGN.md §4.2. Those two now say `-EACCES` as well.

**R11 — unix sockets.** A pathname socket is decided twice. First the name the target passed: a relative
`sun_path` resolved against `/proc/<pid>/cwd` (R6), matched as a cleaned absolute string against the declared
entries and, for the implicit admit, against the nearest filesystem entry (SEMANTICS §5; it holds only for a socket
the run bound, R11a); a name nothing admits is
refused `unmatched`, and one whose cwd could not be read, which R6 leaves relative, is refused
`rule: path-unreliable`, since no entry can be matched against a relative path. Then, for a name that was admitted,
**the socket it resolves to** (SEMANTICS §5: "matched on the resolved socket"). The relay walks the name `O_PATH`
as the task would — from `/proc/<tid>/root` with `RESOLVE_IN_ROOT` for an absolute name, from `/proc/<tid>/cwd`
for a relative one, refusing magic links, whose "self" would be this process — on an OS thread holding the task's
credentials (`unixWalk`, the one walk every unix name takes: a datagram's decision makes it too, R11a, and so does
the path a bind R11a could not record is remembered at, while a recorded bind walks nothing since 2026-10-17; a lookup that fails as the task's may, `ENOENT`, `ENOTDIR` or `EACCES`, is walked again a component at a time
with procfs's `self` and `thread-self` answered for the task and every magic link refused, so its errno is the
task's own and not what this process's pid directory holds, and a walk that ends on procfs, where no socket can be
bound and "self" is this process, is refused `path-unreliable` as `ELOOP` is; a connect whose name only that walk
resolved is refused `path-unreliable` too, since that walk reads each symlink rather than following it, so it is not
held to `fs.protected_symlinks`, and a relay to where it landed could make a connect the task's own would not); reads the path of the inode it reached; walks that path once more in this process's own view,
following no symlink, and goes on only if it reaches the same device and inode (`sameInodeHere`); and admits that
path against the same entries, each taken at its resolved path: a declared entry as it resolved when the loop was built, before the agent ran and never again
for the run, so a symlink the agent later plants where a declared path lies does not move it; a filesystem entry at
`agent.FSRule.Resolved`. Only then does it connect, naming that inode through `/proc/self/fd/<n>`, so the decision
and the connect cannot name two sockets, and a rename after the decision moves the name, not the inode. A socket
the resolution leaves unadmitted is refused with R10's errno and `rule: unmatched`, nothing connected, `dst` still
the name the target passed. A walk that fails as the task's own lookup would (`ENOENT`, `EACCES`, `ENOTDIR`)
answers that errno, recorded `allow` against the entry the name matched, like a relayed `ECONNREFUSED` (§7). A walk
that meets `ELOOP` is refused `rule: path-unreliable` with R10's errno and a refused line: a magic link, which the
relay will not follow, is one the task's own lookup would have followed, so `ELOOP` is not the task's answer, and
the relay cannot tell it from a symlink loop the task would have met too, and answering `ELOOP` recorded `allow`
would be a result the task's own connect would not have got (I3). A relative name from a task
whose root is not this process's is refused `rule: path-unreliable`: an absolute symlink met on the walk from its
cwd would resolve against this process's root. **Assumption, stated:** every path the policy holds is this
process's view — the launcher compiled and resolved it here — and the path the kernel reports for the inode the
task's walk reached is a place in that view only when the task's mount tree is this process's. For a task in
another mount namespace (a container, or a bind mount it made in one of its own) `d_path` builds the string from
the task's mounts, and the same string here can name another file under a write entry while the socket lies
anywhere; a `/`-prefixed string proves nothing about it. So a resolved path that does not reach the same inode
here is refused `rule: path-unreliable`, nothing connected, an absolute name as well as a relative one. A name
longer than `sun_path` once resolved, which the relay used to refuse (`path-truncated`), is reached through the
descriptor like any other.
**Credentials** (I6). The thread takes the supplementary groups, the effective uid and gid (the filesystem ids
follow) and at most the effective capabilities of the thread that trapped, read from its `/proc/<tid>/status`
under R2's bracket (`sys.RunAs`). Its real and saved ids stay this process's: nothing a connect checks reads them,
and while they differ from the task's the task can neither signal nor trace the thread holding its uid. The
thread is never handed back to the Go scheduler and is never the main thread, whose credentials
`/proc/<pid>/status` reports as the process's. So the DAC checks of the walk and of the socket are the task's,
and a stream listener's `SO_PEERCRED` reads the task's uid and gid, at tier 2 as at tier 1. When the credentials
cannot be read, or the thread cannot take them, the connect is refused `rule: relay-credentials`, never made as
this process. At tier 1, where this process holds no privilege, that is whenever the task's supplementary groups
differ from this process's (`setgroups` needs `CAP_SETGID`), its effective uid or gid is not one of this process's
real, effective or saved ids, or its filesystem ids differ from its effective ones. A task whose groups and ids
this process can take and whose effective capabilities differ is not refused: the thread keeps only the
capabilities both hold — dropping one needs no privilege, and one the task has and this process lacks (a task in a
user namespace of its own holds a full set there) is never added — so the relay can refuse a connect the task's own
would make, never make one it would not. **One thing stays this process's:** the pid in
`SO_PEERCRED` (and `SO_PEERPIDFD`) names the supervisor, which at tier 2 is root, so a listener that authorizes by
reading that pid's own credentials, rather than the uid and gid `SO_PEERCRED` carries, sees the supervisor's (Open,
below). **Abstract names** have no filesystem half: matched by raw bytes, leading NUL stripped, never NUL-scanned
(E5), and connected on the same credentialed thread; the relay is also how a declared abstract name reaches a
listener outside the domain's abstract scope (enforce-landlock R7). **Datagram sends** to a unix address are
R13b's: decided on the name they carry and then, as a connect is, on the socket that name reaches in the task's view
(R11a, **Where it is asked**), refused with R10's errno when either refuses, and an admitted one is `CONTINUE`d, best
effort, so the kernel sends it as the agent. **Cost:** a relayed
unix connect adds a `/proc/<tid>/status` read, two `O_PATH` opens, the walk, a `readlink` and the walk again in
this process's view, and, when the
credentials differ (tier 2), one OS thread created and destroyed. Decided once at connect for
`SOCK_STREAM`/`SOCK_SEQPACKET`; at connect and every send for `SOCK_DGRAM` (mirrors R13). This is a required P0 decision, not optional record-only
behavior: spec/backend/CAPABILITIES.md's capability matrix row "unix sockets" lists tier 1 as "seccomp connect;
`RESOLVE_UNIX` on ABI ≥ 9," settling that tier 1 decides unix-socket connects via this package, the same mechanism
as TCP.

> **A notification names a thread, not a process.** The kernel fills a notification's `pid` with `task_pid_vnr(current)`, which is a thread id. `pidfd_open(2)` without `PIDFD_THREAD` requires a thread-group leader — `pidfd_prepare` tests `pid_has_task(pid, PIDTYPE_TGID)` — so passing that id straight through returns `ENOENT` for every notification a secondary thread raised, and a failed duplicate is a refusal. A threaded agent therefore had every connect from a worker refused with `EACCES` against a contract that named the host, recorded as `rule=fd-raced`, blaming a race that never happened. `duplicate` opens the pidfd through `sys.PidfdOpenThread`, which asks for `PIDFD_THREAD` (Linux 6.9) — naming the trapping task exactly — and, when that fails, itself retries the plain form. Below 6.9 the retry is what runs: it succeeds for a thread-group leader and refuses any other tid (`EINVAL` on those kernels; the `ENOENT` above is what current ones answer, measured on 6.17), and on that refusal, whatever its errno, `duplicate` resolves the thread group and opens the leader. The fallback is sound only while the thread shares its leader's descriptor table, so that `pidfd_getfd` against the leader returns the same open file description. A thread made without `CLONE_FILES`, or one that unshared it, has its own table, and `pidfd_getfd` against the leader succeeds whenever the leader has any file under that number; so the fallback asks `kcmp(2)` `KCMP_FILES` whether the two share one table, before the duplicate's `ID_VALID`, and a thread that does not, or a kernel whose `kcmp` cannot answer (no `CONFIG_KCMP`), is refused as `fd-unreadable` (*amended 2026-10-20:* it was `fd-raced`, though nothing raced: the thread's own table is a lasting property, so its every connect and send is refused alike). Only the thread form serves such a thread.

**R11a — a socket the run bound.** *Added 2026-10-16.* The implicit admit of a
pathname socket under a write entry (SEMANTICS §5) holds **only for a socket a process of the run bound**; any other
socket there — one that existed before the run (a daemon an earlier, ungoverned session left running, like Codex's
app-server control socket in `CODEX_HOME`), or one a process outside the run made during it — is refused with R10's
errno, `rule: unix-foreign`, and nothing is connected or sent. Its premise had been "the run created it", which
holds for `multiprocessing`, Ray and local MCP servers the agent starts, and not for a socket another program serves:
what such a daemon runs is outside the run, so reaching it reached around the contract. A `unix:` entry still admits
any socket it names, on purpose.
**How the run's sockets are known.** Under a `net:` section the filter notifies `bind(2)` (enforce-landlock R11c;
with a listener policy it is notified already). `handleBind` records the socket object a pathname unix bind names
before it answers, on a `pidfd_getfd` duplicate: its inode on sockfs and its `SO_COOKIE`, which no other socket of
this boot carries, and the moment it found the socket bound to nothing (`runSock.binds`; up to four binds of one
socket, `bindRecsMax`). A socket that is bound already is not recorded: that bind fails `EINVAL`, so a run holding
another program's listener cannot make it its own by calling `bind` on it. **Nothing of a bind's name is recorded or
trusted.** Which bind of a socket takes, with which bytes and from which directory, is the run's to race — a sibling
rewriting the address after this loop read it, a descriptor swapped after it was duplicated, a symlink or a
directory changed before the kernel's lookup, a bind this loop continued with no record — and none of it changes
whose socket object it is: a socket a task of the run held, bound to nothing, and called `bind` on is the run's,
whichever bind then took. Which **file** it is bound to is decided by identity, below (`struct unix_diag_vfs`).
*Amended 2026-10-17 (ADR 0041's note of that date):* a bound socket was attributed to a **directory** — the device a recorded bind's walk
reached in the task's view, chosen by matching the name the kernel reported for the socket (`UNIX_DIAG_NAME`) to a
recorded bind — and that directory was consulted where `st_dev` is not the superblock's. Each fix closed some orderings and more were found, because the name is the run's: a bind continued with no record (an address
read as abstract or as `AF_INET`, a descriptor of a socket bound already, a full set) that took the socket with bytes
matching its own earlier, failed record; a rewrite or a swap onto a recorded name after a symlink was changed at
leisure, for an absolute name or a relative one from one cwd; a descriptor swap whose other socket, the record of the
other directory, was gone or bound since. Each admitted a foreign btrfs socket repeating the run's inode number,
`allow/fs.write`. The earlier rules — `unknownBinds`, a relative name trusted from one cwd
(`relNameFromOtherCwd`, whose scan of the whole set made one sweep cost up to 58 ms under the set's lock),
the cwd recorded with each bind — went with the attribution, and a bind no longer walks its name.
Deciding the implicit admit, the loop asks the kernel's socket diagnostics (`sock_diag(7)`, an exact
`SOCK_DIAG_BY_FAMILY` lookup of a recorded socket by inode and cookie with `UDIAG_SHOW_VFS`) which file the recorded
sockets are bound to, and admits the socket file the name resolves to only when it is one of them (`owns`). A
socket's binding is kept once a lookup has seen it bound: it cannot change while the socket lives (a second bind
fails `EINVAL`, and the binding holds its file's inode), so a bound socket is looked up again only when its kept
binding names the file being decided, to learn that it still lives. A socket seen bound to nothing (a bind still in
flight, or one that failed on a socket the run keeps open) is asked again by each notification that needs it, newest
first. **The work is bounded per notification** (`unixPass`, *amended 2026-10-16*): every R11a
question one notification asks — one per addressed message of a `sendmmsg` batch — shares what it learnt, so a
socket is looked up at most once per notification, the sockets bound to nothing are swept once, and the path of
each unrecorded bind is `stat`ed at most once, so at most 256 times per notification, whatever binds other workers
record meanwhile, and outside the set's lock (a path is the run's choice, and a deep one is a long walk; a `stat`
stale by the end of a pass changes only which refusal is named, `unix-bind-unrecorded` or `unix-foreign`, never a
refusal into an admit). *Amended 2026-10-16:* those `stat`s were remembered only until the set
changed, and any bind another worker recorded changed it, so a binder racing a `sendmmsg` batch to foreign sockets
restored a `stat` of every unrecorded path per message, under the set's lock: 16,896 for one 66-decision
notification holding 256 paths, measured on the test machine (6.17) at about 41 ms of the lock for short
paths and about 4.2 s for paths of some 2,000 components under the run's own write entry. Mountinfo is asked about a file at most once per decision, however many
recorded bindings share its low 32 bits (btrfs subvolumes repeat inode numbers); and at most 256 lookups per
notification may answer "bound to nothing" or fail (`unixPassUnboundMax`). Past that, a file no recorded socket is known to be bound to is refused `rule:
unix-origin-unread` rather than looked up further: fail closed, and the rule says the origin was not read rather
than that the socket is foreign. A lookup that finds a socket bound, or gone, is not counted: each happens once in a
socket's life (its binding is kept, a gone socket forgotten), so that cost is one lookup per bind the run made. Until
then a decision about a file no recorded socket is bound to looked up every recorded socket, once per message, under
the set's lock, so a run holding 4,096 sockets made a 1,024-message batch cost 266,240 lookups (65 decisions before
the batch was refused), seconds of the run's own loop, with binds waiting behind it. Rejected: caching only negative
answers per file for a notification, which leaves one decision's cost at a lookup per recorded socket; a lookup of
every socket in the network namespace (`NLM_F_DUMP`), whose cost is the namespace's socket count, which the run can
grow without bound. `struct
unix_diag_vfs` reports the file's superblock device (`d_sb->s_dev`) and its inode's low 32 bits, which is narrower
than a file's identity, so a binding names the file only when all of these hold: the low 32 bits are the file's; the
superblock is the file's — `stat(2)`'s `st_dev` when the two are equal, and otherwise the device
`/proc/self/mountinfo` names for the mount the file was reached on (`STATX_MNT_ID`; mountinfo's third field is
`sb->s_dev`), since on btrfs `st_dev` is the subvolume's own anonymous device, the top-level subvolume's included,
and never the superblock's; and the file's inode number fits in 32 bits. Where `st_dev` is the superblock's (ext4,
xfs, tmpfs) that is the file (`ownsFile`). Where it is not — a btrfs subvolume, the subvolumes under one superblock
repeating their inode numbers, or an overlayfs layer — the pair is shared by files that are not one, and the file is
the socket's only when both of these hold (`ownsIfAlone`; *amended 2026-10-17*): **its birth time**
(`statx` `STATX_BTIME`) lies within 50 ms before (inode times are the kernel's coarse clock) and ten seconds after
one of the socket's recorded binds (`bindBornWithin`), and no later than this loop first saw the socket bound — the
socket was bound to nothing when a bind of it was recorded, so the file any bind of it makes is born after, and it was
bound when seen, so its file was born before; and **no socket outside the run shares the pair** in this network
namespace: one `NLM_F_DUMP` of the namespace's unix sockets (`UnixDump`), begun after the file was reached or more
than a second after it was born (`dumpSettle`: the kernel's bind makes the file and then hashes the socket, so a
socket bound to a file born a second before is in the table; a pass reuses a dump for every file it so covers),
lists none bound to a file with that superblock and inode
number but sockets of the run's (`alone`), a connected stream or seqpacket socket excepted — an accepted one reports
its listener's file (`unix_stream_connect` copies the path), and neither it nor a bound socket that connected can be
reached through a file, by a connect or by a datagram. **A relayed connect's dump is one pass of the kernel's walk**
(`dumpNeed`, `needConnect`; *amended 2026-10-17*): `unix_diag_dump` fills a dump
one datagram at a time, walking each hash bucket of the namespace's socket table whole under that bucket's lock, and
starts the next datagram at a saved (bucket, index) pair, so a socket that leaves that bucket between two datagrams —
closed, bound, connected, or made at its head after the walk passed and closed again, any socket of the run's — shifts
the sockets after it, and the next datagram skips one that was bound throughout; within one datagram nothing is
skipped. The run paces that churn itself, and its own colliding socket shares the foreign one's bucket (a pathname
socket is hashed by its inode number), so a dump read across datagrams could leave out the very foreign socket
`alone` asks about (`TestUnixDumpIsOnePassOrRefused`: 1 to 3 of 4,000 sockets bound throughout were missing from 9 of
40 dumps while a sibling made and closed sockets). So the dump socket first receives with a 32 KiB buffer, which
makes the kernel fill the dump's first datagram into 32 KiB (`max_recvmsg_len`, capped at `SKB_WITH_OVERHEAD(32768)`
since Linux 4.6); what that datagram charges the receive queue (`SO_MEMINFO`) says whether it got that allocation
rather than a page; the first datagram must leave room for one more socket's message (`unixDumpMsgMax`) and the next
must hold no socket — else `errUnixDumpSplit`. A stream or seqpacket socket's connect reaches through a file only an
unconnected listener of its own type (`unix_find_other` refuses another type, and a connected stream never listens),
so its dump leaves connected sockets out (`udiag_states` without `TCP_ESTABLISHED`): a desktop's connected streams
are most of its unix sockets (some 830 of 950 on the test machine), and the rest fit one pass up to some 600. A datagram
socket's connect asks for every socket, since a datagram socket another one connected to reads `TCP_ESTABLISHED`
(`unix_dgram_connect` sets both ends) and still takes datagrams and connects from any; on a busy desktop that does
not fit one pass. A datagram's decision is best effort whatever the dump says (residual (1) below), so it reads the
whole list however many datagrams it takes (`needDatagram`). A file born before the socket's first recorded bind, or
after it was seen bound, is another file (`unix-foreign`, or `unix-bind-unrecorded` as below); a file born during the
run in no recorded bind's window (a bind this loop never saw, or one delayed past ten seconds), one whose filesystem
reports no birth time, a pair a socket outside the run shares, a dump the kernel refuses, a namespace holding more
than 65,536 unix sockets (`unixDumpMax`), a relayed connect whose dump does not fit one pass, a decision past one
notification's 16 dumps (`unixPassDumpMax`), and a dump that lists no socket of the run's under the pair
(`errNotListed`) are refused `unix-origin-unread` (a file born so of a socket bound more than four times,
`unix-bind-unrecorded`). A dump lists none when the run's socket closed after it was found bound, when a datagram's
dump read across datagrams skipped it, or when the decision's list leaves it out because it cannot take the connect:
a connected stream or seqpacket socket (any connect), or a datagram socket another socket connected to, which reads
`TCP_ESTABLISHED` and is not in a stream or seqpacket socket's connect's list (*amended 2026-10-17*). The kernel refuses such a connect too (`ECONNREFUSED`, or `EPROTOTYPE` where the two types
differ), so only the errno and the ledger's rule differ from its answer; before the one-pass list a stream connect
to the run's own datagram socket so connected was admitted and met `EPROTOTYPE`. So a foreign
file that existed before the run's bind is refused by its birth time whatever the bind's name did, one born during
it in this namespace by the dump, and the run's own socket while a live socket outside the run shares its pair
(a collision two subvolumes' inode numbering makes possible) or where the dump does not show it, fail closed. The dump is made only there, after the
birth time admits, so its cost — the namespace's socket count, which a run can grow — is bounded per decision and
per notification and paid by no file whose `st_dev` is its superblock's; that cost is why (above) a
dump was not taken to find every remembered socket's binding. A file whose low 32 bits match one of the run's sockets while its own inode
number is wider (XFS `inode64` on a large filesystem, tmpfs mounted `inode64`), or whose mount this process's
mountinfo does not list, cannot be told apart, and is refused `rule: unix-origin-unread`. A socket the run renamed is
still its own: the binding follows the inode, not the name. mountinfo is kept open and read again when the kernel
flags it (`POLLPRI`, a mount or unmount in the namespace) or on a miss, and only where `st_dev` is not the binding's
device. *Amended 2026-10-16:* the match compared the binding's device with `st_dev`, which
never matched on btrfs, so every socket the run bound on btrfs (Fedora's and openSUSE's default) was refused
`unix-foreign`; and it confirmed a low-32-bit match by `stat`ing the path the run's bind had named, a path under a
write entry the run can unlink and hard-link a foreign socket onto, so it proved nothing, and refused a socket the
run had renamed. A socket that is gone answers `ENOENT`, an inode
number reused by another socket `ESTALE` (the cookie), and either drops it from the set, so a match is never a
socket that took a gone one's place; a live socket's binding holds its file's inode, which cannot be reused while it
lives. The lookup needs no privilege for a socket in this network namespace. A kernel without `sock_diag` for
`AF_UNIX` (`CONFIG_UNIX_DIAG`, or a `unix_diag` module it cannot load: no modprobe, modules disabled), or one that
refuses the lookup, fails closed: the socket is refused `rule: unix-origin-unread`. Such a kernel answers the lookup
`ENOENT`, as it answers one for a socket that is gone, so the loop tells the two apart by asking about a socketpair of
its own (once it answers, for the process's life; unanswered, again at most once a second). The KVM harness loads the
module in each guest (test/vm/root-suites.sh's default `VM_MODULES`); `tego doctor` names a kernel without it on
its unix sockets row, and a run under a `net:` section warns at its start. The set holds at most 4096 live sockets (`runSocketsMax`); past that a newly bound socket is not
remembered and is refused, with one warning. A full set is pruned of its gone sockets before a bind is turned away,
at most once a second (`runSocketsPruneEvery`): a bind sooner than that after a prune is unrecorded without looking
up every recorded socket again.
**A bind that cannot be recorded** is remembered as one, and a socket under a write entry that no recorded socket
is bound to is then refused `rule: unix-bind-unrecorded` rather than `unix-foreign`, which would say that no process
of the run bound it: when the bind's address could not be read, or the directory of a bind whose socket could not be
read walked, for every such socket for the rest of the run, and otherwise when the path that bind's walk reached
names the socket file now. At tier landlock
the unprivileged supervisor can neither read the memory of a non-dumpable process (`PR_SET_DUMPABLE` 0: `ssh-agent`,
which sets it at start) nor duplicate its descriptors, so a socket such a process of the run binds is
never recorded, and the run's own clients of it are refused: declare it with a `unix:` entry (`ssh-agent -a
<path>` under a write entry, and `unix:<path>`). That is an unprivileged supervisor's: one holding `CAP_SYS_PTRACE` —
the root tiers', and tier landlock's when tego runs as root — passes `ptrace_may_access`'s dumpable check, reads the
bind and duplicates the socket, so the socket is recorded and is the run's own (`TestUnixForeign` as root: a non-dumpable *child of the run* bound it, so admitting it is right; a
non-dumpable process outside the run is refused `unix-foreign` at every privilege, since its bind is never
notified). A socket bound past `runSocketsMax`, and one whose descriptor could not be read, are unrecorded the same
way, at the path their walk reaches in the task's view. *Amended 2026-10-16:* every one of these
was refused `unix-foreign`.
**A datagram to a name that names nothing** — no file where the task's own lookup of it lands (`ENOENT`, `ENOTDIR`) —
is refused with that errno, the one the kernel's own lookup would have met, and `rule: unix-absent`; it is not
continued, since a symlink made before the kernel's lookup would decide where it goes. A `sendmmsg` batch carrying
one is refused whole with R10's errno, as any batch with a refused destination (R13b). *Amended 2026-10-16:* it was refused `unix-foreign` with R10's errno.
**Where it is asked.** A connect: on the socket the name resolves to as the task (R11's second decision), with the
identity of the inode the walk reached, on the relay's thread. A datagram (R13b): on the socket its name reaches when
the task's own lookup resolves it (`unixWalk`, the relay's walk, with this process's credentials, which decide only
whether a lookup may pass, never where it lands), matched by that socket's place against the declared entries'
resolved paths and the write entries as a connect's is (`decideResolved`), and through a write entry only when the
run bound that socket, since a datagram is never relayed; a name the walk cannot resolve (`ELOOP`, procfs, a
relative name from another root, a place this process cannot see, a directory it may not search) is refused
`path-unreliable` with R10's errno. A batch walks each name once (`unixTarget`). The kernel looks the name up again
when it sends, R13b's stated limit, and what that leaves is the first residual below. *Amended 2026-10-16:* a datagram was matched on its lexically cleaned name and its file `stat`ed in
this process's view: a symlink the agent put at a name a `unix:` entry declares sent it outside every entry under
that entry's `allow`, a `..` after a symlink and a `/proc/self/cwd` link reached a socket outside every entry while
their spelling named the run's own, and a declared entry reached through a symlinked directory by a `..` name was
refused. Under a contract with no `net:` section nothing is decided (R7), the name is
not looked up, and bind is not notified. The refusal is this loop's own: a kernel program of the run admits any name
under a write entry, so `kernelRefusal` leaves it, and any refusal of where a datagram's name lands, to R10's
errno. `compile --test` answers a socket under a write
entry `allow`, the run's own case, since it cannot know which process will bind one.
**Decision and rejected options.** Recording the run's binds and asking the kernel was chosen over: (1) removing the
implicit admit and requiring a `unix:` entry for every socket, which fails closed too, but `multiprocessing` and Ray
bind sockets under random names in a temporary directory, so a contract would need a directory-wide grant there that
admits every foreign socket under it (`/tmp/tmux-<uid>/default`, `/tmp/.X11-unix/X0` under a `/tmp/` write entry) —
the very hole this closes; (2) the socket file's birth time against the run's start, which misses a socket an outside
process makes during the run and rests on `STATX_BTIME`, which not every filesystem reports; (3) reading the
listener's `SO_PEERCRED` pid after the relayed connect, which decides after the connection exists and cannot serve a
datagram; (4) recording the bound path rather than the socket, which a rename or an unlink and rebind by another
process moves; (5) a kernel peer check in the decision plane (`unix_stream_connect`, `unix_may_send`, the socket's
run by `tego_unix_sock_run`), which tier 2 and tier landlock have no hook for and which is the condition below.
*Added 2026-10-16 (ADR 0041's note of that date):* for where a name lands, (6) `stat`ing its
lexical spelling in this process's view, which resolves procfs's `self` as this process and drops a `..` after a
symlink; walking only names with a `..` (a first fix), which missed magic links and a symlink at a declared name; the
exec walk a component at a time for every name (`FSTarget`), which follows the task's own magic links where the
connect relay refuses them, so a connect and a datagram to one name could be decided apart, and costs a descriptor
per component; and for which bind took, (7) keeping a socket's first record, which a second bind after a failed one
moves; marking a socket whose binds named two devices unsettled (a first fix), which refused the run's own retried
socket and stayed blind to a rewritten address; trusting a relative name's recorded directory whenever no bind had
gone unread (a first fix), which a sibling's rewrite onto the socket's other recorded bytes, a descriptor swap, or a
second process binding the same bytes from another cwd moves with no race the loop can see, so a relative name's
directory is now trusted only when the same bytes could not have resolved from another cwd — no other recorded bind
of the socket, and no other socket not yet seen bound, bound for them from a cwd other than the matched record's
(`relNameFromOtherCwd`); one relative bind from one cwd, and two binds of one socket from one cwd (a second bind
after a failed one), still settle; trusting an absolute name's recorded
directory after a bind went unread (a first fix), since an unread bind may have taken the socket after a symlink on
the path changed, so `unknownBinds > 0` now leaves even an absolute name unknown — chosen fail-closed over a
per-socket count of unread binds, which is unsound because an unread bind counted before a socket's record can still
take it after (its kernel bind lands after `CONTINUE`), and the disclosed cost is that one `ssh-agent` at tier
landlock refuses the run's own btrfs or overlayfs sockets under a write entry for the rest of the run; taking
`UNIX_DIAG_NAME` as proof of a file's identity (a name the run controls), where it only chooses among
the run's own recorded binds and refuses one that is none of them; and `SIOCUNIXFILE`, the bound file's full
identity, which needs `CAP_NET_ADMIN` (the root tiers only): not built, the condition that closes residual (4) there.
*Amended 2026-10-17 (ADR 0041's note of that date):* for which file is a socket's, (8) the directory
attribution of (6) and (7) itself, however its accounting is tightened — every bind continued with no record counted,
a run-wide index of names to the directories they reached never pruned, a socket with two names unknown — since a
name only predicts where the kernel's lookup will land, and the run defeats the prediction: a swapped descriptor makes
every bind notification, an `AF_INET` one included, a possible taker of any socket of the run's bound to nothing, so
a sound count refuses every btrfs socket once the run has bound an IP port; (9) a proposal to decide by the socket object as
written — decide by the socket object and take the namespace's sockets bound by the file's pair as the candidates,
the file being the run's when every one is — adopted for the object and the dump, not alone: `sock_diag` dumps one
network namespace while a pathname socket is reached from any (`unix_find_bsd` searches the kernel's table of bound
sockets), so "no other candidate listed" is not "none bound" and "no candidate" is not "a stale file" (the birth
time covers what a dump cannot see, save residual (4)), and an accepted connection reports its listener's file, so
"every candidate the run's" would have refused a listener of the run's with a connection open; (10) binding in this
process on the duplicate, which would make the file certain but either stores this process's spelling as the
socket's name — a pinned parent's `/proc/self/fd/<n>/<name>` or the bare final component, so `getsockname` and the
peers' view of it change, and `multiprocessing` hands its children the listener's `getsockname` — or resolves the
task's bytes again, and takes the bind out of the task's Landlock domain, credentials and umask; (11) `SIOCUNIXFILE`
at the root tiers, which needs a descriptor of the socket once it is bound: one kept from the bind keeps a socket the
run closed bound and connectable, and one found again in the run's descriptor tables is a scan per socket, and tier
landlock could do neither, so two tiers would decide one socket apart; (12) a probe connect, or `SO_PEERCRED` and
`UNIX_DIAG_ICONS` after the relayed connect, which put a connection into the run's or a daemon's listener before
the decision; (13) the file's `ctime`, which a link, a rename or a `chmod` by the run under its write entry moves on a
foreign file, where `btime` cannot be set. (2) stays rejected as it was: the birth time here is checked against the
binds of the socket the binding matched, not against the run's start, and a socket a process outside the run makes
in this namespace during the run is in a relayed connect's dump, made in one pass (*amended 2026-10-17:* this said "in the dump" of every dump, which a run churning its own sockets defeats for a
dump read across datagrams). *Added 2026-10-17, for a dump's completeness:* (14)
a second dump that must list every socket the first one did, which narrows the skip without closing it — a socket
the dump never listed shifts the bucket as well: one made at the bucket's head after the walk passed it and closed
before the next datagram (7 to 12 sockets bound throughout skipped from one dump of 12,000 by churning only such
sockets, none of them ever listed), or a pending connection, which the dump never lists (it has no inode yet,
`sock_i_ino` 0) and which goes when its listener closes; (15) refusing only when the dump took several datagrams
while the namespace's socket count changed, since churn keeps the count, and every dump of every state takes several
datagrams on a desktop; (16) one pass of every socket for every decision, which a desktop's connected streams take
past one datagram, refusing every btrfs socket of the run's there for connects that cannot reach them; (17)
disclosing the skip for connects too: the run paces its own churn, and a relayed connect's
line is not best effort; (18) the kernel's unix socket iterator for BPF (`iter/unix`, which batches a whole bucket
under its lock), at the root tiers only, so tier landlock would decide apart; (19) `/proc/net/unix`, whose reads
resume by an offset within a bucket the same way, and which names sockets by the names they were bound with.
*Added 2026-10-17, for the run's socket a connect's list leaves out:* (20) asking a
stream or seqpacket socket's connect for every state and leaving out by type afterwards, so that the run's own
datagram socket another socket connected to is listed and the connect meets the kernel's `EPROTOTYPE`: the connected
streams come back into the list and take it past one pass on a desktop (16), refusing the run's own listeners there
to spare a connect the kernel refuses anyway; (21) admitting a connect whose list shows no socket under the pair at
all, since nothing listed can take it: the line would say `allow` on the run's own socket while the list showed
none, and the socket's closing after it was found bound reads the same.
**The root tiers.** The supervisor decides every unix connect and every addressed unix datagram first at tier 2 and
3 as well (connect and send are never left to the plane, enforce-landlock `planeSkips`), so R11a holds there for
both. The kernel layers stay name-level backstops wider than it: tier 2's `cgroup/connect_unix`/`sendmsg_unix` rows
and the plane's step D rows admit a name under a write entry (enforce-cgroup-observe §5 R7), and so does Landlock's
`RESOLVE_UNIX` grant on every write entry at ABI ≥ 9 (enforce-landlock R21), since none of them sees which process
bound a socket. **Residual, disclosed:** (1) a datagram whose name, or the file that name leads to, changes between
this loop's lookup and the kernel's — a sibling thread rewriting the name in memory, or any process of the run
renaming a file onto it, swapping a symlink on it or on a directory above it (`renameat2(RENAME_EXCHANGE)` on two
symlinks under a write entry, one to the run's socket and one to a foreign socket, reached a daemon's datagram
socket 97 times in 6 s in a probe at tier landlock) — reaches a socket the run did not bind, under an `allow` line marked
`best_effort` (spec/record/v1/README.md), and so, where `st_dev` is not the superblock's, does a datagram to a file
whose pair a socket outside the run shares when the datagram's dump, read across datagrams, skipped that socket
because sockets left its hash bucket in between, which a run churning its own sockets can bring about (*added
2026-10-17; a relayed connect's dump is one pass and skips nothing); (2) under `io_uring: true` at tier `bpflsm`, which this loop never sees, an
`io_uring` connect, and an `IORING_OP_SENDMSG` or `IORING_OP_SENDTO` with a unix address, reach any socket under a
write entry, and a socket bound with `IORING_OP_BIND` (Linux 6.11+) is never recorded, so it is refused
`unix-foreign`, which there means that no bind this loop saw made it; (3) a foreign socket whose inode number shares
its low 32 bits with the wider inode number of one of the run's sockets, on the same superblock and subvolume, is
indistinguishable to `sock_diag` and admitted (only on a filesystem with inode numbers past 2^32); (4) on btrfs or overlayfs, where `st_dev` is not the
superblock's, a socket bound by a process in another network namespace — which this namespace's `sock_diag` does not
list, while a pathname socket is reached from any namespace — to a file in another subvolume or layer of the same
superblock, born within one of the run's socket's bind windows (at most ten seconds after a bind of it this loop
answered) and repeating that socket's inode number, is indistinguishable from the socket's own file and admitted, and
so is one a process in this namespace binds so, whose bind has made its file but is not yet in the kernel's table
when the dump passes it (`unix_bind_bsd` creates the file, then hashes the socket): the run cannot create a network
namespace (E24), cannot pace a process outside it, and needs such a process to bind on cue at the number it arranges.
For a relayed connect that holds because its dump is one pass (above): no churn of the run's thins it. *Amended
2026-10-17:* a dump read across the kernel's datagrams skipped a socket bound
throughout when sockets left its hash bucket in between, which the run's own churn does, so (4)'s "cannot pace" did
not hold for this namespace's sockets either, and a relayed connect admitted a skipped foreign socket
`allow/fs.write`. *Amended 2026-10-17:* (4) was a run changing the filesystem between this loop's walk of a bind's name
and the kernel's bind, so that the name landed in another subvolume than the one recorded; later fixes found it
reached with no race at all — a bind continued with no record, a rewrite or a swap onto a recorded name after a change
made at leisure, a swap whose other socket was gone — and no bind's name is attributed now, so none of those reaches
anything: a foreign file that existed before the bind is refused by its birth time. A dump also cannot list a
socket whose bind stalled between making its file and hashing the socket for longer than `dumpSettle` before the
dump began, which, again, a process the run cannot pace would have to do. The condition that
closes (1), (2) and (4) is the plane's peer check above (`internal/bpf`, step D's owner), and for (4) at the root
tiers also `SIOCUNIXFILE` on a socket of the run; (3) closes with a full-width identity of a bound socket's file, which unprivileged `sock_diag` does not
report (`SIOCUNIXFILE` needs `CAP_NET_ADMIN`). Relaying the datagram, as a connect is, was rejected for (1): the
receiver would read this process's pid in `SCM_CREDENTIALS`, and ancillary data and sizes past `sendBytes` could not
be carried (R13b, "Nothing is sent from here"). **Cost**, on the test machine (6.17): one exact lookup is 16 to 22 µs
(`BenchmarkUnixBound`: a netlink socket, one request, one reply), paid as the bounded-work rule above says; a
datagram adds a walk of its name in the task's view, once per name per notification (`unixTarget`): the task's
root opened from `/proc/<tid>` (and its cwd for a relative name), one `openat2`, and the place read back and walked
again here (`readlink`, `openat2`, `statx`), 7 allocations and 192 B; *amended 2026-10-16:*
`BenchmarkUnixTarget` is 25 to 39 µs on the test machine at load 30 to 36, where `BenchmarkUnixBound` read 23 to 27 µs in
the same session (16 to 22 µs on a quiet box), against the one `statx` of the name in this process's view (2 to
5 µs) it replaces, so a datagram decided through a write entry costs about twice what it did on the real kernel, and
a bind paid the same walk of its directory beside its duplicate and two reads (*amended 2026-10-17:* a
bind walks nothing now, one duplicate and two reads; where `st_dev` is not the superblock's, a decision the birth time
admits pays one dump of the namespace, 0.18 to 0.27 ms for 932 unix sockets, 56 of them listed, on the test machine at load
16, `BenchmarkUnixDump`, once per notification for the files it covers, 16 at most — *amended 2026-10-17:* a dump begins with an exact request of inode 0 and a `getsockopt`, and a relayed stream
connect's lists the namespace's unconnected sockets only, 72 to 89 µs for 69 of them on the test machine at load 13 to 16,
where a datagram's, every socket in as many datagrams as it takes, is 193 to 218 µs for some 950, 4.6 KiB and 16 to
18 allocations either way; and one sweep
that first sees 256 of the run's sockets bound, in a set of 4,096 with four binds each, is 0.76 ms of the fake
kernel's under the set's lock, `BenchmarkR11aSweepSettles`, where an earlier measurement read 58 ms with the cross-socket
scan, and `BenchmarkNotificationRoundTrip`, `BenchmarkSendMMsgTail` and `BenchmarkSendMMsgForeignUnix` are unchanged
in bytes and allocations against the code before, six alternating rounds, `scripts/bench-gate.sh`, no finding); the
fake kernel's batches are
unchanged in allocations (`BenchmarkSendMMsgTail`'s alternating relative unix batch 5,534 against 5,540, 502.4 against
503.6 KiB, the walk made once per name for the batch) and `BenchmarkNotificationRoundTrip`'s paths are unchanged in
bytes and allocations; where `st_dev` is not the binding's device (btrfs) a mountinfo lookup adds a `poll` and a map read
(`BenchmarkMountDev`), and a full read of mountinfo after a mount changes. *Amended 2026-10-16:*
a socket is looked up once in its life to learn its binding; after that, a decision about a file one of the run's
bound sockets names pays one lookup per notification, however many messages name it, and one about a file none
names pays one lookup per recorded socket bound to nothing, at most 256 per notification, and none for the bound
ones; before, every decision about a file not cached paid one lookup per remembered socket. `BenchmarkSendMMsgForeignUnix` (fake kernel, 1,024 messages alternating between two socket files no process of
the run bound; the test machine, load 6 to 9, five runs of five, before against after in one session): with 4,096 recorded
sockets bound elsewhere, 266,240 lookups and 15.0 to 17.3 ms per batch before, none and 0.35 to 0.40 ms after; with
200 bound to nothing, 13,000 lookups and 0.84 to 0.88 ms before, 200 and 0.38 to 0.51 ms after; with 4,096 bound to
nothing, 266,240 lookups and 13.6 to 14.5 ms before, 256 and 0.42 to 0.43 ms after (refused `unix-origin-unread`).
On the real kernel a lookup is 14 to 25 µs (`BenchmarkUnixBound`, same session), so such a batch went from about 4 s
of the loop's time to at most about 6 ms. `BenchmarkSendMMsgTail`'s alternating relative unix batch is unchanged:
809 to 866 µs before, 782 to 866 µs after, 5,535 against 5,539 allocations and 543,276 against 543,603 B per batch
(the pass). Earlier, `BenchmarkSendMMsgTail`'s alternating relative unix batch (1,024 messages to two of the run's
sockets, fake kernel) went from 551 µs to 916 µs of this package's own work, allocations unchanged (5,530 per batch); after a fix (2026-10-16: `statx` for the name, the match in `owns`), 635 to 690 µs against 824 to 1,647 µs for the
code before it in the same session on a loaded box, 5,530 allocations and 512,577 B per batch against 5,530 and
512,090 B, and `BenchmarkMountDev` is 275 to 297 ns with no allocation; on a real
kernel each such message adds the lookup above, so a long batch of datagrams to sockets under a write entry costs
milliseconds more, all before the answer. A connect pays it once beside the relay's own walk. Bind costs a duplicate
and two reads. A decision that reaches the unrecorded binds' paths pays one `stat` of each, at most 256 per
notification, outside the set's lock (measured at 2.5 µs for a short path and 249 µs for one of some 2,000
components on the test machine); `BenchmarkSendMMsgForeignUnix`'s case with 255 unrecorded binds (fake kernel, six
alternating runs against the code before, the test machine) is 482.0 KiB and 2,470 allocations per batch on both sides,
with medians of 433 µs before and 410 µs after inside the noise, and the other cases and `BenchmarkSendMMsgTail`
are unchanged in bytes and allocations.
(`TestUnixConnectIsDecidedOnTheResolvedSocket`,
`TestUnixSocketUnderWriteDirIsAllowed`, `TestKernelDecidedDatagramIsRefusedHere`, `TestUnixBoundNamesTheFileStatNames`
on the real kernel, `TestRunSocketsForgetGoneSockets`, `TestR11aWorkIsBoundedPerNotification`, `TestOwns`, `TestUnixDatagramOnBtrfs`,
`TestUnrecordedBindIsNotCalledForeign`, `TestUnrecordedPathsAreStatedOncePerNotification`,
`TestUnixDatagramIsDecidedWhereItLands`, `TestUnixDatagramBatchWalksANameOnce`,
`TestR11aDecidesTheBoundFileByIdentity` (which replaced `TestBindRecordsTheDirectoryTheKernelBindsIn` on
2026-10-17), `TestR11aDumpsOncePerNotification`, `TestR11aDumpBegunAfterTheFileIsReached`,
`TestR11aConnectDumpIsOnePass`,
`TestUnixAbstractNamesAreNotPaths`, `TestParseUnixDump`, `TestUnixWalkLandsWhereTheKernelDoes`,
`TestBoundFileIsBornInItsBind` (a sibling rewriting the bind's `sun_path`), `TestUnixDumpListsWhatAConnectCanReach`,
`TestUnixDumpIsOnePassOrRefused` (a sibling making and closing sockets while the namespace is dumped)
and `TestConnectUnixAsUnderSwapsConnectsOnlyTheInodeAdmitted` (the last component's symlink, a directory's symlink and
a `..` through a directory moved or renamed, swapped while relayed connects run) on the real kernel, `TestUnixForeign` at
tier landlock end to end — a renamed socket, a name that names nothing, a symlink planted at a declared name, a
`..` after a symlink, a `/proc/self/cwd` link, a socket bound through that link, a non-dumpable process outside the
run, and a non-dumpable child's socket among its cases, and as root a supervisor that reads that child's bind — and,
as root on the fixture btrfs in the KVM guest, `TestUnixBoundOnBtrfs`, `TestIntegrationUnixRelayOnBtrfs`,
`TestIntegrationUnixRelayDotDotOnBtrfs`, `TestIntegrationUnixRelayRebindOnBtrfs`,
`TestIntegrationUnixRelayMagicBindOnBtrfs` and `TestIntegrationUnixRelayStaleCollisionOnBtrfs`.)

**R11c — an approved unix connect.** *Added 2026-10-19 (ADR 0008's note of that date; the model below
replaced, the same day, the earlier rules — see the amendment at the end).* **A pathname `net.ask` `unix:`
scope is a place**: the path it declares, resolved once when the loop is built, as a declared `unix:` entry's is
(`resolveUnixDeclared`, which is
`agent.ResolveUnixPlace`, compile's own resolution of `NetRule.UnixResolved`, so `compile --test` places it alike):
the path is walked from the root one name at a time, each symlink read (`PlaceLink`) and followed whether or not its
target exists yet (`realpath -m`: the run may make that target), a name that names nothing yet kept, and neither the
path nor a link's target is cleaned lexically, so a `..` after a symlink applies once that symlink is followed, as the
kernel's lookup applies it. The declared path itself is the contract's, which compile makes absolute and cleans
lexically as it does every contract path (`compiler.abs`): a `..` written in it removes the name written before it,
and the person is shown that cleaned path. The walk takes at most 1024 names (the link targets' included) and 40
links, so one placement is at most 1024 reads, each a `readlinkat` of one name in its directory opened with `openat2`
`RESOLVE_NO_SYMLINKS` (`PlaceLink`, `agent.ReadPlaceLink`): a walk of under `PATH_MAX` bytes through directories the
placement already found no symlink in. A name the walk kept that an agent's thread makes a symlink afterwards fails the
next read `ELOOP` and ends the placement, so a race cannot make the later reads follow it (*amended 2026-10-19*: each read was a `readlink` of the whole path, which followed such a name, up to 40 links of
`PATH_MAX` bytes per read, 1.17 s for one placement). One placement so costs at most 1024 reads through plain
directories, raced or not: 35 to 56 ms for a path 1100 directories deep. A read still interrupted (`EINTR`) after
`ReadPlaceLink`'s retries ends the placement too, the name's kind unknown, as does a read failing with anything but
`EINVAL`, `ENOENT` or `ENOTDIR` (the descriptor table full, `ENOMEM`, `EIO`, `EACCES`: *amended 2026-10-19; such a name was kept as if it were no link). A path it cannot place within that, a link
loop or such a race included, is its spelling as given. An abstract scope is its
bytes. A unix connect is the scope's when its name reaches that place in the task's view (`unixScopeOf`): the loop
walks the name as the relay will (`unixTarget`, a final symlink followed), and, when only the last component names
nothing yet, the directory with that component (a socket the run has not bound yet), or, when that component is a
symlink that leads nowhere yet, where it leads, placed as a scope is (`resolveUnixDeclared` from the directory the
walk reached, in this process's view); a name whose directory does not
exist yet reaches no place and is the scope's when its cleaned absolute spelling (a relative one joined to the cwd) is
the scope's declared or resolved path, or when the name, uncleaned (as passed when absolute, else joined to the cwd
`/proc/<tid>/cwd` names), placed as a scope is (`resolveUnixDeclared`, a symlinked directory before the missing one
and a `..` after it followed), lands at the scope's place, as a connect to a host port is asked before anyone knows
whether it listens. A connect's name the placement cannot place within its bound is no scope's, and is decided where
it leads (nothing connects at the scope's place unasked: the relay refuses it there `unix-ask-scope`); so what an
agent's chain of dangling links costs the worker that places it is bounded. So
the scope's spelling, a relative name from any cwd, the canonical spelling `getcwd` gives, a symlink or a symlinked
directory are all the scope when they reach its place; a name the walk cannot place (a magic link, procfs, another
root or view) is no scope's, and the relay refuses it `path-unreliable` with nobody asked. Such a connect, when no
declared `unix:` entry admits its name, is not admitted by the write entry around its spelling (`decideUnix`) and
stays trapped while a person decides, through the broker as a held TCP connect does (op `connect`, hold `connect`,
target `unix:<path>` — the scope's declared path whatever name the task passed — or `unix:@<name>`, rule
`net[unix:...]`), so `--always`, `ask.on_timeout` and `ask.timeout` are the broker's. Whoever bound the socket at the
place, the run included, it is asked. **A name that reaches any other place is not the scope's**, and is decided where
it leads as every relayed connect is (`decideResolved`, R11a): a declared entry's place, the write entry around it for
a socket the run bound, `unix-foreign` for one it did not. So a hard link to the run's socket at the scope, or the
name it was renamed to, is the run's own socket, admitted by the write entry as a socket it bound there afresh would
be; one bound outside the run is refused `unix-foreign` under such a name, and asked only at the scope's place. A
scope's place that a decision reaches with no person asked — an addressed datagram (never asked), or a name
the loop's walk placed elsewhere and the relay's own walk at the scope (the agent repointed it in between) — is
refused `unix-ask-scope` (`decideResolved`), never admitted by a write entry. A scope inside a write entry is only as
fixed as that directory: the agent can rename or link another socket of the same filesystem onto the place, and a
person who approves approves the place, which the target says. A denial, a timeout or a broker that cannot answer
refuses it `EACCES` with `ask-denied`, `ask-timeout` or `ask-unavailable` and connects nothing. An approval is carried
out by R11's relay, as the task, on a thread holding its credentials: a pathname is admitted by the approval only
where the task's own lookup then lands at the scope's place (`relayUnix` with the scope), on the inode it reached;
a name the agent repointed during the wait is decided where it then leads, as above, with no person's authority; an
abstract name, which has no filesystem half, on the approval alone. The allow line carries `authority: human`. A
relayed connect of an approved abstract name at a root tier that fails `EPERM` or `EACCES` — its grant lapsed (it
lives a second, counted from before the relay), or another program refused it — answers the task that errno and is
recorded `observed` (`grantedUnixVerdict`): no breadcrumb says which program refused a unix name, and the line cannot
say the approved connect happened. An approved TCP connect at a root tier is read as every relayed connect is
(`kernelDecided`): an `EPERM` the run's breadcrumb names is the kernel's refusal, one it does not name `observed`.
*Amended 2026-10-19:* both were recorded allow, `authority: human`, for a connect
that did not happen. What cannot carry an approval is refused `ask-unavailable` before anyone is asked: an `ask.hold`
other than `connect` (compile refuses one with a `unix:` scope too, for a unix connect carries no TCP bytes for
`first_write` to hold nor an HTTP request for `request`), and, at tiers 2 and 3, an abstract name when the run's
kernel cannot take the one-connect grant the relay needs (`Options.GrantUnix`: the relay connects with the task's own
bytes, which `connect_unix` or the plane decides). Where it can (the tier-2 handle's `GrantUnix`, enforce-cgroup-observe
R7, enforce-plane R14), the grant is made after the approval and before the relay, for the duplicate's socket cookie
(which the supervisor reads, having checked the duplicate is `AF_UNIX`), the run's gen and exactly that name, and
revoked when the relay returns; a socket not `AF_UNIX` or a grant the kernel refuses (its map full) refuses the
connect `ask-unavailable` and connects nothing. Two connects of one socket hold no grant at once, to one name or two,
since the kernel's row is the socket's and the name its value: the second waits for the first's to be withdrawn, as
R13d's grants do (the granter's `creditRows`, by the map's own key, amended 2026-10-19 and 2026-10-20; `TestGrantsOfOneRowTakeTheirCreditsInTurn`). A pathname needs no grant there: the
relay names the inode it resolved as `/proc/self/fd/<n>` from the launcher's cgroup, which those programs admit from
the relay alone. A gate's ask on a unix connect an entry admits is still refused as unsupported (`performAskConnect`).
*Amended 2026-10-19:* earlier versions had built
on the rule that the scope's socket is never admitted implicitly under any name, even when the run bound it.
That needs the identity of "the scope's socket" across renames and links of files in the agent's own write entry: the
rounds marked a socket of the run the scope's when a walk of its bind, or a decision, found it at the scope's path
(`scopeMark`, `bindScopeMark`, `markScope`, a bind's mark held until `UNIX_DIAG_NAME` said which bind took), stat'ed
every scope path at every implicit admit, and refused what they could not read (`unix-ask-scope-unread`); a rename
with no decision between still lost the mark, every fix left another branch, and the property guards nothing,
since the run reaches its own server under any name by binding a fresh socket. And the scope was matched twice, by the
spelling the task passed before the ask and by the resolved place after it, so a relative or `getcwd` name in a
project reached through a symlink was refused `unix-ask-scope` with nobody asked, and a scope through
a symlink that led nowhere at start was refused `unmatched` once approved. Rejected: keeping the
marks (a trap on every rename and link of every run would be the only closure, and it would still decide nothing a
fresh bind cannot); reading the bound name `UNIX_DIAG_NAME` reports (the bytes the task passed, relative to a cwd the
loop no longer knows); matching the scope by its spelling with the place as a second check (two decisions that
disagree); and asking about the run's own socket under every name (the clients of a server that publishes its socket
by a rename would each be asked about a socket the run made).
(Tests: `TestAskUnixHoldsTheConnectAndRelaysTheApprovedSocket`, `TestAskUnixScopeIsThePlaceTheNameReaches`,
`TestAskUnixScopeSpelledThroughASymlinkIsAskedByEveryName`, `TestAskUnixScopeThroughALinkThatDanglesAtStart`,
`TestAskUnixScopeWhoseSocketIsNotThereYet`, `TestAskUnixApprovalConnectsOnlyTheScopesPlace`,
`TestAskUnixScopesPlaceReachedOnlyByTheRelayIsRefused`, `TestApprovedAskConnectCarriesTheKernelsRefusal`,
`TestResolveUnixPlace`, `TestResolveUnixPlaceIsBounded`, `TestAskUnixPlacementOfAConnectsNameIsBounded`,
`TestResolveUnixPlaceDoesNotFollowANameMadeALinkAfterItsRead`, `TestResolveUnixPlaceFollowsTheKernelsFortyLinks`,
`TestSysKernelPlaceLinkFollowsNoLinkBeforeItsName`; end to end
at tier landlock, `TestIntegrationAskUnixApproveDenyAndTimeout`,
`TestIntegrationAskUnixScopeIsAPlace`, `TestIntegrationAskUnixScopeSpellings`; the kernel grant at tiers 2 and 3,
`TestUnixApprovalOnRealKernel`, `TestPlaneUnixApprovalOnRealKernel`, `TestUnixApprovalRowsPurgedOnRealMaps`; end to end
as root, `TestRootAskUnix`.)

**R12 — TCP Fast Open.** `sendto`/`sendmsg`/`sendmmsg` with a destination address on an unconnected `SOCK_STREAM`
fd is decided by the same host:port match as R7. `sendmmsg` is included because the kernel's Fast-Open path is
reached identically through it (`__sys_sendmmsg` → `___sys_sendmsg` → `tcp_sendmsg_fastopen`), so a rule covering
only the one-message forms would be evadable by calling the batch form with `vlen=1` and the identical `msghdr`;
Landlock's `CONNECT_TCP` rule is port-only and cannot see the host (enforce-landlock R6), so it is not a backstop
for this. The batch form is **refused whatever the destination matched** — see R13c. **`MSG_FASTOPEN` is decided
here even on a stream socket that already has a peer.** Without it such a send is R13a's (the kernel ignores the
address), but the peer is only what `getpeername` on the duplicate showed: `CONTINUE` hands the syscall back, a
sibling thread's `connect(fd, {AF_UNSPEC})` — R4's allowed disassociation — can land first, and
`tcp_sendmsg_fastopen` then connects the now peerless socket to the send's own address (measured on 6.17: connect,
`connect(AF_UNSPEC)`, then `sendto(MSG_FASTOPEN)` to a second listener delivers there). Deciding it costs nothing
legitimate: on a socket that keeps its peer the kernel answers the send `EISCONN`, which an allowed relay passes
through as the real result and a refusal replaces with R10's errno. Allowed (one-message forms):
complete the send on the `pidfd_getfd` duplicate — read the buffer/`iovec`s bounded
to 64 KiB, `sendto`/`sendmsg` the same bytes to the same address on the duplicate (same open file description, so it
really transmits on the target's connection) — response carries the real byte count or errno. The `iovec`s are
read as the kernel copies them: up to the first buffer that faults (a `NULL` base with a length, or one that reads
short), so the relay sends that prefix and answers its length, never the bytes after the fault; where the kernel
sends nothing the relay sends nothing and answers the kernel's errno — `EMSGSIZE` for an `msg_iovlen` past
`UIO_MAXIOV` (1024), `EFAULT` for an `iovec` array that cannot be read or a first buffer that faults; a send carrying
`MSG_ZEROCOPY` is refused instead, `rule: zerocopy`, for the reason R7 gives. An `EPIPE` on a stream or seqpacket
socket without `MSG_NOSIGNAL` (a send after `shutdown(SHUT_WR)`) is where the kernel also raises `SIGPIPE` on the
calling thread, which on the duplicate is this process's; so every relayed send (this rule's, R7's guarded
datagram, the address-less relays below) raises it on the trapping task through a pidfd taken before the answer
and sent just after it: the thread's own on Linux 6.9+ (`PIDFD_THREAD`), the process's below.
Refused: `-EACCES` before any byte leaves the kernel, same as R10. **`MSG_FASTOPEN`
with no address**
is decided too, wherever connects are (a `net:` section, or an IP socket under the `models[]` guard), though it names
no destination: after a `CONTINUE` the kernel copies the `msghdr` again
(`___sys_sendmsg`), and a `msg_name` a sibling thread wrote in between is where `tcp_sendmsg_fastopen` connects a
peerless socket. On an IP stream socket `sendmsg` is relayed on the duplicate with no address, which gets the
kernel's own answer to the send as read — `EINVAL` with no peer, `EISCONN` with one, or, on a socket connected with
`TCP_FASTOPEN_CONNECT`, the send to the address its connect named — and writes no line, since nothing new is
decided; ancillary data and `MSG_ZEROCOPY` are refused as above. The batch form is refused whole, `rule:
batch-send` (R13c). A unix
stream socket refuses a `msg_name` (`unix_stream_sendmsg`) and is continued. `sendto`'s address is a register, which
no sibling can rewrite, so a `sendto` with none needs nothing here.

**R13 — UDP.** **R13a (connected):** decided once at `connect()`, exactly like R7/R9/R10 (glibc's resolver connects
before sending) — block-capable. **R13b (unconnected):** `sendto`/`sendmsg`/`sendmmsg` with `msg_name` set — address
read and matched (R7). A destination the policy refuses is **refused** with R10's errno before a byte of the call
leaves, and its one line is that refusal, `reason: net-not-allowed`, with no `best_effort`. A destination the
policy admits is **`CONTINUE`d**, its line `allow` with `best_effort`: the kernel reads the address again after
this decision, and a sibling thread can rewrite it in between — the unprivileged tier's stated best-effort/TOCTOU
limit (capability matrix: "address read: refused when refused, an admitted one continued and read again"). A refusal
needs no race: answered with an errno the call sends nothing, whatever the memory says afterwards, so only an allow
is exposed, which is what `best_effort` marks. Under a contract with no `net:` section nothing is refused (R7), and
every datagram is continued as before. io_uring's send operations never reach this loop: the filter refuses
`io_uring_setup` (enforce-landlock R10) save where the tier-3 plane decides every submission in the kernel.
*Amended 2026-10-16:* the response was **always `CONTINUE`**,
regardless of verdict, so a refused datagram left the kernel under a refused line marked `best_effort`. Under
`net.dns.mode: off`, which removes the resolver exception (R14), a lookup sent from an unconnected socket reached the
machine resolver and its answer came back, while the same lookup from a connected socket was refused at its
connect; Codex's WebSocket client resolves that way. `TestDNSOffRefusesEveryLookupForm`,
`TestRefusedDatagramIsNotSent`, `TestDNSOffRefusesConnectedAndUnconnectedLookups`,
`TestRefusedUnixDatagramIsNotSent`; `BenchmarkRelayDatagram/refused` measures the path (Changes, 2026-10-16).
*Amended 2026-10-05:* where a kernel program of the run decides an addressed datagram's destination
on the kernel's own copy of the address (`Options.KernelDatagrams`: `cgroup/sendmsg4` and `sendmsg6` for UDP, and
for a unix name `cgroup/sendmsg_unix` on 6.7+ or the decision plane's `socket_sendmsg` below it, enforce-plane
§2.11), a datagram that program refuses is refused here with that program's errno (`EPERM`; `EACCES` for the plane)
rather than continued, and its one line is that refusal, `reason: net-not-allowed`, with no `best_effort`: a
destination no entry admits, and a unix pathname not spelled canonically (`<write entry>/./x.sock`, which R11's
cleaned match admits and the programs refuse; `rule: unmatched`, since no row is looked up for it). Continued, the
first was recorded refused with `best_effort`, "recorded without enforcing" of a refusal the kernel enforced, and
the second allow (enforce-cgroup-observe §5 R7). Only what such a program decides is refused with that program's
errno, where the protocol's own checks before it pass, so the agent sees the errno the kernel would give it: an
admitted destination is continued (its line allow with `best_effort`: the kernel decides its own copy), and a
refused one the programs do not decide — a relative unix name, which they leave to this tier, an address the
protocol fails first (UDP port 0; a family the socket does not speak; a unix address `unix_validate_addr`
refuses), a UDP datagram to an IPv4 or v4-mapped address on an `AF_INET6` socket (`IPV6_V6ONLY` decides there) —
is refused with R10's errno like any refused datagram (amended 2026-10-16; it was continued). A `sendmmsg` batch is
never refused with a program's errno: one that carries a refused destination is refused whole with R10's errno,
and an admitted one's lines stay best effort. Nothing is sent from here:
a unix datagram would carry this process's real uid and pid to a receiver reading `SCM_CREDENTIALS`
(`maybe_add_creds`) besides ADR 0041's rejected alternative 7, and a relayed UDP datagram would lose the control
messages (QUIC's GSO segments, ECN), `MSG_ZEROCOPY` and sizes past `sendBytes` that tier 2 delivers today
(`TestKernelDecidedDatagramIsRefusedHere`, `TestTier2DatagramLineIsTheKernels`). **Cost**, `BenchmarkRelayDatagram`
on the test machine's 6.17 over a real listener, the agent's time per addressed UDP `sendto`, median of five runs of 20,000,
measured under a load average near 11 (other guests running), so every figure carries that load: continued 66 µs,
refused here for the kernel 54 µs, relayed under the guard 51 µs, against 43 µs for
`BenchmarkSeccompNotifyRoundTrip`'s `mkdirat` in the same run. The refusal adds nothing over the continued path
(the budget: at most 20 µs over it); it reads `SO_DOMAIN` once and sends nothing. `TestIntegrationUDPFlood`
sends 10,000 addressed datagrams a second for 10 s, every tenth refused here: on the test machine the target kept its
schedule (10.0 s), the loop held a notification 42 µs on average, under R22's 200 µs, and every datagram had its
one line.
An address this tier cannot match at all (an unrecognized family, or `AF_UNSPEC`, which is one outside
`connect(2)` — R4, E4) is refused with R10's errno, under a contract with no `net:` section too where it is
`AF_UNSPEC`, because continuing it would let bytes leave for a destination nothing read, and would record them
under a `dst` that does not name where they went. An IP socket under the `models[]` guard (R7) is where an admitted
datagram is not continued: one whose address the guard refuses is refused with R10's errno like any refused
datagram, one it admits is relayed on the duplicate rather than continued (or refused when it cannot be relayed
whole), and every addressed `sendmmsg` batch is refused whole,
because there the guard's verdict is the only one at tier 2 as well and a continued address is read again by the
kernel after the decision. The same holds for a `sendmsg` there whose header names no
destination (`msg_name` `NULL`, or a zero `msg_namelen`), on a datagram, raw or seqpacket socket: continued, the
kernel would copy the header again and a `msg_name` a sibling wrote in between would reach the model around the
forwarder with no line at all, so it is relayed on the duplicate with no address and the payload as read — to the
socket's peer, or the kernel's own `EDESTADDRREQ` without one — and writes no line, as the continued send did not;
one that cannot be relayed whole is refused (`ancillary-data`, `datagram-size`, and `zerocopy` as R7 says). A batch
with no address in any message is continued: residual (d) of R7. A network gate ([gate.md](gate.md) R4) relays a
datagram it admits from the same copies, *on an IP socket only (amended 2026-10-05)*: a unix datagram it admits is
continued as R13b says, so the kernel sends it as the agent, from the agent's cwd, Landlock domain and credentials.
Sent from here, a relative name resolved against this process's cwd, an abstract name left the agent's
abstract-socket scope behind, and at tiers 2/3 a root-only socket accepted it with the receiver reading this
process's credentials — R7's reason for never relaying a unix connect (`TestGateNeverRelaysUnixDatagrams`,
`TestIntegrationGateNeverRelaysUnixDatagrams`). A `sendto` with an address pointer and a zero
`addrlen` names no destination either (`move_addr_to_kernel` copies nothing): it is continued with no line under any
contract, since its length is a register no sibling can change, and the kernel sends it to the peer or fails the
short name `EINVAL` (UDP, Fast Open). Outside the guard an unaddressed datagram is
continued as before, and the same rewrite is R13b's best-effort limit, which the root tiers close with
`cgroup/sendmsg`. `sendmmsg`'s array is read as far as the kernel sends: `__sys_sendmmsg` clamps `vlen` to
`UIO_MAXIOV` (1024) and runs every message up to it, so the handler reads `min(vlen, 1024)` headers in one
bracketed read, then the address of each addressed message in order: every one among the first 64, and past them
each one up to and including the first this tier cannot decide, which refuses the batch and ends the read. One
`CONTINUE` answers the whole syscall **when the socket is a datagram or raw one** and every address read is one
this tier can match and the policy admits. A batch with even one that it cannot match, or one the policy refuses
(amended 2026-10-16), is refused whole with R10's errno: the same `msghdr` passed to `sendmsg` is refused, so
continuing the batch form would make `vlen=1` the way around that refusal — the evasion R12 closes for the stream
shape — and reading only the first 64 messages would have moved that route to `vlen=65`.
**Lines.** Each of the first 64 addressed messages is recorded as its own `net` event. Past them one line at most
is written, so one call writes at most 65, and only for a refused batch: the message that refused it when that lies
past the 64th — one this tier cannot place, or a destination the policy refuses, matched with the socket's `proto`
exactly as one before the 64th — else the first addressed message there. A continued batch carries no refused
destination, so past the 64th it writes no line (before 2026-10-16 it was continued with a `refused` / `unmatched`
line marked `best_effort` for the first such destination, and the datagrams left). A batch whose only addresses lie past the 64th therefore takes
the socket, is decided and records like any other; only a batch in which no message the kernel sends carries an
address is `CONTINUE`d with no duplicate taken and no line. On a refused batch an undecidable message is
`rule: unmatched` and a destination the policy would have admitted `rule: batch-send` (the batch, not the host,
refused it), so the refusal always has a line naming an address it was for; none carries `best_effort`, because
this refusal was enforced. A header the read does not reach is one the kernel is about to read, so it fails closed
as R5's unreadable header, past the 64th as before it. **Residual:** past the 64th message of a continued batch,
a destination the policy admits is not recorded; every one there was decided, and a refused one refuses the batch.
Each datagram of a continued batch leaves, as every admitted R13b datagram does, and the kernel reads its address
again. **Cost**, measured on the test machine (6.17, a real listener, one
`sendmmsg` of 1024 addressed `AF_INET` datagrams to a loopback receiver, timed in the target, five runs each):
about 1.4 ms end to end when the handler read only the first 64 addresses, about 2.5 ms once it read all 1024 —
roughly 1.1 µs per message past the 64th, one bracketed read each, before the answer. Deciding the messages past
the 64th against the policy left that figure where it was (the same measurement repeated, to a declared and to an
undeclared receiver, 21 runs each: 2.2 to 3.1 ms, medians between 2.4 and 2.5 ms with and without the decision);
a run of consecutive messages carrying the same address bytes is decided once — which is also why that
measurement says little about deciding: every tail message there carried the same bytes, so the tail was decided
once, not 960 times. The worst case is a tail whose consecutive messages differ, one decision each. Measured on
the fake kernel (`BenchmarkSendMMsgTail`, the test machine), a 1024-message batch alternating two declared `AF_INET`
destinations costs about 0.1 ms more than one repeating a single destination (0.26 ms against 0.16 ms of this
package's own work); alternating relative unix paths costs about 0.25 ms more in this package, and on a real
kernel each such decision adds a `readlink` of `/proc/<pid>/cwd` (1.1 µs measured here) and an `ID_VALID`, so
roughly 1.5 to 2 ms on top of the 2.5 ms above, all before the answer. A batch that long can exceed R22's
soft ceiling, which counts it and aborts nothing; a batch of 64 or fewer reads the same bytes as before, its headers
now in one read instead of one per message. The 64-message recording cap, like R3's argv figures, is an unsourced
P0 default — §11; the 1024 read bound is the kernel's own.
*Source routes (amended 2026-11-02, GAPS C34).* A datagram's own control messages can route it: `udp_sendmsg`,
`raw_sendmsg` and `ping_v4_sendmsg` take the first hop from an LSRR or SSRR option in an `IP_RETOPTS` message, and
`udpv6_sendmsg` and its raw and ping twins from an `IPV6_RTHDR` one (`fl6_update_dst`; a type 2 header from any
task), connected socket or not, so a datagram this rule admitted went to an address in the route, which no entry
admits and which neither this decision nor the root tiers' `sendmsg4/6` see. This loop only tested
`msg_controllen`. Under a `net:` section it now reads each message's control buffer, at most `msgControlMax` (4,096)
bytes of it, before deciding a `sendmsg` (addressed or not) or a `sendmmsg` (every message the kernel sends), and
walks it as `for_each_cmsghdr` does. A message at `SOL_IP` of type `IP_RETOPTS` or `IP_OPTIONS` (which Linux answers
`EINVAL` as a control message; refused with the others rather than rest on that), or at `SOL_IPV6` of type
`IPV6_RTHDR` or `IPV6_2292RTHDR`, or a buffer longer than the read, whose rest the kernel walks unseen, refuses the
call, the whole batch for `sendmmsg`, with R10's errno and one `refused` line, rule `relay-source-routed`, on an IP
socket that is not a stream one (`SO_TYPE` and `SO_DOMAIN` read on the duplicate; a domain that cannot be read counts
as IP). TCP and SCTP read no message of these levels, and a unix socket none of either, so there the call goes on to
its own decision. A buffer with a message `CMSG_OK` refuses is left to the kernel (`EINVAL`, nothing sent); a read
that comes back short, a fault included, counts as a route and is refused (R5: the kernel's own copy runs in the
task's context, where a page this read faulted on can be there by then). A contract with no `net:` section admits every IP destination and its control messages are not read. The
read is a snapshot of the agent's memory, as R13b's address read is, and the kernel copies the buffer again after a
`CONTINUE`: a sibling thread can write a route in between, at every tier, since no tier's kernel program sees the
control messages. That is the residual; a datagram this loop relays (under a network gate or the `models[]` guard)
carries no ancillary data at all (`ancillary-data`), so the race does not reach it. Benign messages (`UDP_SEGMENT`,
`IP_TOS`, `IP_PKTINFO`, `SCM_RIGHTS`) change nothing; a send that carries control data costs one bounded read of
the agent's memory between two `ID_VALID` checks, and one without costs nothing (`TestControlRoutesParse`,
`TestSendMsgRoutingControl`, `TestSendMMsgRoutingControl`, `TestIntegrationSourceRoute`).
*Pending frames (amended 2026-10-19; rebuilt 2026-10-20, ADR 0008's
design note of that date).* A socket that holds a pending frame (a send with
`MSG_MORE`, a `sendfile` or `splice` whose last write carried it, or `UDP_CORK` set) appends every later send to it
before `udp_sendmsg` or `udpv6_sendmsg` reads `msg_name`, and before the run's `sendmsg4/6` runs; a raw IP socket
sends the joined frame by its first send's route. While a frame is pending, where a datagram's bytes go is the
socket's, not the call's, and a line naming the call's address would name a destination the bytes did not reach. So
in a run that decides datagrams (`agent.RuleTable.DecidesDatagrams`: a `net:` section, a guarded `models[]` endpoint or
a net gate) no socket comes to hold a frame through a syscall of the run, and that is decided where a frame forms, on
the socket alone (`frame.go`): its `SO_TYPE`, `SO_PROTOCOL` and `SO_DOMAIN`, read from the duplicate, never an address
the call carries. A socket that can hold a frame is an `AF_INET` or `AF_INET6` datagram socket other than a ping
socket (UDP, UDP-Lite, or one whose protocol could not be read) or a raw IP socket; one whose domain cannot be read
counts as one (`frameSocket`). On such a socket:
- a `sendto`, `sendmsg` or `sendmmsg` whose flags argument (a register no sibling can rewrite) carries `MSG_MORE` is
  refused with R10's errno, rule `datagram-corked`, before anything about its destination is decided, addressed or
  not, a batch whatever its first address's family (`refusesFrame`, asked first by every send handler); the filter
  notifies a `sendto` with no address that carries the flag (enforce-landlock R11d), and a send without it is not
  read for this at all. A socket that cannot be read is refused as resolveSocket fails it, `fd-exhausted`,
  `fd-unreadable` or `fd-raced`, whatever socket it then is, a TCP one included (the failure table's rows);
- `setsockopt(UDP_CORK)` at `SOL_UDP` or `SOL_UDPLITE` is refused with R10's errno whatever the value, recorded
  `refused`, op `setsockopt`, rule `datagram-corked` (R1, `refuseCork`): the value is in the agent's memory, and the
  run can cork no socket, so there is none of its own to uncork;
- a `sendfile` or `splice` into it is refused with R10's errno, rule `datagram-corked`, with no destination
  (`spliceInto`): `splice_to_socket` marks every write but a call's last with `MSG_MORE`, a splice with
  `SPLICE_F_MORE` its last one too, and so does `splice_direct_to_actor` a `sendfile` whose file ended before its count.
  Into any other descriptor, a file, a pipe or another socket, either is continued, and so is one whose descriptor is
  not open (the kernel answers `EBADF`). One whose descriptor cannot be duplicated or its type read may be such a
  socket and is refused with R10's errno, but recorded `refused`, op `sendfile` or `splice`, target `fd <n>`, rule
  `fd-exhausted`, `fd-unreadable` or `fd-raced`, with no `proto`: nothing says its bytes were bound for a network
  (amended 2026-10-20). At tier 1 `pidfd_getfd` refuses every descriptor of a process that made
  itself non-dumpable (`EPERM`), so such a process's every `sendfile` and `splice` is refused in a run that decides
  datagrams, a file copy included (the failure table's row).

A datagram this loop sends itself (R7's guard, a gate's relay, R13d's approval, an unaddressed relay) meets one
precondition (`frameFree`): it carries no `MSG_MORE`, and on a UDP or UDP-Lite socket `UDP_CORK` reads clear on the
duplicate, a cork that cannot be read counting as set, else it is refused `datagram-corked`; R13d reads it before the
prompt and again just before the relay. The run sets no cork, so that read covers a socket the run was handed corked.
At tiers 2 and 3 an approved datagram's line is checked against the kernel as well (R13d). Before, each send path asked
its own question: a batch took the socket's protocol from its first address, so a UDP batch with `MSG_MORE` whose first
addressed message named an admitted unix name was continued, its frame left pending to the socket's peer, and the next
approved datagram to an asked port went to that peer under the person's allow naming the asked port, which received
nothing (end to end at tier 1); the other way round, a unix socket's `MSG_MORE` datagram to an IP
address was refused for a frame it cannot hold (`TestAPendingFrameIsDecidedFromTheSocketAlone`, which asks every send
shape on every kind of socket; `TestTheRunCannotCorkASocket`, `TestASendfileOrSpliceIntoAFrameSocketIsRefused`,
`TestAMoreSendWhoseSocketCannotBeReadIsRefused`, `TestIntegrationAskUDPPendingFrame`, `TestRootAskUDP`'s `pending frame`
cells). *Residual, disclosed:* a run that swaps a descriptor between this loop's read of the socket and the kernel's use
of the number (a sibling's `dup2` of a UDP socket over a TCP one while a `MSG_MORE` send of the TCP one is held) forms
a frame no layer sees; so does a socket handed to the run (inherited, or received over a unix socket) holding a
`MSG_MORE` frame its creator left, which no read from user space shows. A later relayed datagram joins such a frame,
whose destination the run admitted, under a line naming the relayed address: at tier 1, at the tier-2 fallback and, for
the relays that take no credit (the guard's, a gate's), at every tier; an approved datagram at tiers 2 and 3 is
recorded `observed` instead (R13d). A run that declares `io_uring: true` (no `ask`, no gate) sends through its ring
unseen. Refusing a relay on a connected socket would not close the race: a frame an earlier `send(MSG_MORE)` left
survives `connect(AF_UNSPEC)`, and the peerless socket's next addressed datagram joins it (ADR 0008's note of
2026-10-19).

**R13c — `sendmmsg` on an unconnected stream socket.** The same syscall on a `SOCK_STREAM`/`SOCK_SEQPACKET` fd with
no peer — or with one, when the call carries `MSG_FASTOPEN` (R12) — is R12's Fast-Open shape, not R13b's, and is
**refused with R10's errno whatever the destination matched**,
before the kernel runs it. R12's relay cannot be reproduced for a batch: `sendmmsg` reports each message's byte
count by writing `msg_len` back into the caller's own `mmsghdr` array, and this loop reads the target's memory but
never writes it, so any count it answered would be the fabricated result I3 forbids — the same reason ancillary data
is refused rather than dropped. Nothing is lost: `sendto` and `sendmsg` are relayed in full, so Fast Open to a
declared host stays available through them. The event per recorded addressed message (R13b's **Lines**: each of
the first 64, and one past them) carries the destination's own decision,
with `rule: batch-send` on a destination the policy would have admitted (the batch form, not the host, is what
refused it) and `rule: unmatched` on one it would not; neither carries `best_effort`, because this refusal was
enforced. The socket type is therefore read **before** anything is answered, and a failed `pidfd_getfd` or `SO_TYPE`
fails the syscall closed (`rule: fd-raced`) rather than assuming a datagram socket; an unreadable `mmsghdr` header
fails closed the same way (R5), since being unable to read a header is not the same as there being no destination
in it. A batch in which every message the kernel sends (up to its `UIO_MAXIOV` clamp) carries no address —
`msg_name == NULL`, or a `msg_name` with `msg_namelen == 0`, which `__copy_msghdr` treats the same way
(`kmsg->msg_name = NULL`) — ordinarily continues to its already decided peer (R13a). Under the `models[]`
guard the socket is duplicated first: an IP datagram, raw or seqpacket batch returns `ENOSYS`, recorded as an
enforced `batch-send` refusal, so single-message fallback cannot race a second header copy. A batch carrying
`MSG_FASTOPEN` under a `net:` section or the guard is refused on an IP stream socket, also `rule: batch-send`
(R12; the kernel's own answer without an address is `EINVAL` or `EISCONN`). Empty batches remain no-ops. `sendmsg` reads a header with a zero length the same way. An address past the 64th message counts as one before it: a batch whose first 64 messages carry
none and a later one does is refused here, with a line naming that address, just as it would be with the address
first. A connected stream socket's batch without `MSG_FASTOPEN` is `CONTINUE`d undecided and unrecorded (R13a) —
unless a message the kernel would send carries an address this tier cannot decide, which refuses the batch as on
every other socket type (R4).

**R13d — an approved UDP destination.** *Added 2026-10-19 (ADR 0008's note of that date).* A `net.ask`
`udp://host:port` scope, and a bare `host:port` one, which names TCP and UDP (SEMANTICS §5; agent-contract R22), holds
UDP at the syscall under `ask.hold: connect` (the only hold such a contract compiles with):
- *An addressed datagram* (`sendto`, `sendmsg`) on a UDP socket whose destination nothing admits and that such a scope
  reaches (the ask resolver's match on `udp`, then the run's resolved-address checks, as for a TCP ask) is held
  (`askDatagram`). Its address and payload are copied first, and what a relay cannot reproduce is refused before anyone
  is asked, as R13b's relay refuses it: ancillary data, a payload not read whole, `MSG_ZEROCOPY`, a source-routed
  socket, a corked socket (`datagram-corked`, R13's pending frames: `frameFree`, read again just before the relay; a
  datagram with `MSG_MORE` never reaches the prompt, `refusesFrame` refused it); an address length or payload the
  kernel refuses gets the kernel's own answer. A person then sees op `send`,
  target `udp://ip:port` and the scope's rule; `ask.timeout`, `ask.on_timeout` and `--always` are the broker's, as for
  any held request. An approval sends the copied payload to the copied address on the duplicate (the relay of R12), so
  a sibling thread that rewrites either during the wait changes nothing that leaves; its line is `allow` with authority
  `human`, or, when the run's `sendmsg4/6` refused the relay after all (a grant that lapsed), the kernel's refusal or
  `observed` (`kernelDecided`), never a person's allow of a datagram that did not leave. At tiers 2 and 3 a relay the
  kernel answered with success whose credit `sendmsg4/6` left untaken (the revoke says so) is recorded `observed`,
  authority `human`, under the scope's rule: the hook takes that credit only for that socket's datagram to that
  destination, and `udp_sendmsg` and `udpv6_sendmsg` append to a pending frame before they run it, so the datagram
  joined a frame and its bytes went to that frame's destination (R13's residual), or, rarely, a refresh admitted the
  destination by an ordinary row while a person decided; no breadcrumb tells the two apart, the kernel recorder naming
  connects (`creditTaken`, amended 2026-10-20, ADR 0008's design note;
  `TestAnApprovedDatagramWhoseCreditTheKernelLeftIsNotAPersonsAllow`). A denial, a timeout or a broker
  that cannot answer refuses with that reason (`ask-denied`, `ask-timeout`, `ask-unavailable`) and sends nothing.
- *The socket's later datagrams.* An approval covers the same socket's later datagrams to the same `ip:port` under the
  same scope, by the socket's `SO_COOKIE`, which the kernel never reuses while it runs: each is still copied, relayed and
  recorded `allow` by `human`, and at a root tier granted one at a time; nobody is asked again, as nobody is asked again
  for the stream a TCP approval opens. Another socket is asked again (or answered by a standing `--always`). Under a
  net gate the approval is kept with the verdict, score and rule the gate gave the datagram the person saw (the request
  carried them), and covers only later datagrams the gate scores the same: a person decides a scored request in the
  light of its score, which the broker never keeps as a standing answer, and a score that changes during the run (the
  gate's hosts for the address are the resolver's live ones) is asked again
  (`TestAskDatagramApprovalIsKeptAtTheScoreAPersonSaw`, amended 2026-10-19). The loop
  keeps at most 1,024 such approvals a run; past that an approval is not kept and the socket's next datagram is asked
  again, never admitted unasked.
- *A UDP connect* to such a destination is held as a TCP connect is (`performAskConnect`), op `connect`, target
  `udp://ip:port`; once approved, the socket's sends name no address and the kernel sends them to the peer the
  connect decided (R13a).
- *Tiers 2 and 3.* The run's `connect4/6` and `sendmsg4/6` refuse the destination, which no row admits, so an approval
  first grants the run's kernel one operation of that socket to exactly that destination (`Options.GrantDatagram`, cgroup's
  `Handle.GrantDatagram`, which takes the socket's `SO_COOKIE` and `SO_DOMAIN` read from the duplicate, never its descriptor number, ADR 0023 F8; `GrantConnect` with proto `udp` for a connect): a credit in `tego_connect_approvals` keyed by
  the run's slot and gen, the socket's cookie, the family the hook reads, UDP and the address, live for a second, taken
  once and withdrawn when the relay returns. A datagram to an IPv4 destination of an `AF_INET6` socket is keyed `AF_INET`,
  as `sendmsg4` reads it (`udpv6_sendmsg` hands it to `udp_sendmsg`). Detach, Prepare's reclaim and the reaper purge the
  map's rows by slot, as for a TCP credit. The map holds one row per key, written only when absent, and a revoke
  deletes by key, so the granter, which builds the key, holds each row from its grant to its revoke, by the exact key
  value it writes (cgroup's `creditRows`; amended 2026-10-19; rebuilt 2026-10-20, ADR 0008's design
  note): a second operation that would write the same row waits until the
  first's credit is withdrawn, then grants its own, whatever its own spelling differs in: an approved socket's
  datagrams sent by two threads, a UDP socket's connect and datagram, two scopes of one IPv6 link-local address (the key
  drops the zone), a second abstract-name connect of one socket to any name (`tego_unix_approvals` keys its row by the
  socket's cookie alone and keeps the name in the value). A wait past a second, or the run's end, refuses it
  `ask-unavailable` with nothing granted or sent. The supervisor serializes nothing: it used to, by a key of its own that
  drifted from the map's, by the name and then by the zone, and two approved datagrams to one link-local address on two
  scopes then collided, one refused `ask-unavailable` (`TestGrantsOfOneRowTakeTheirCreditsInTurn`,
  `TestAGrantWaitsBoundedAndForANotPreparedHandleGrantsNothing`; on the kernel `TestConnectApprovalOnRealKernel` and
  `TestDatagramApprovalOnRealKernel` read a revoke's untaken report). A UDP connect of an `AF_INET6` socket to an IPv4 peer (mapped or `AF_INET`
  spelled) is refused `ask-unavailable` before anyone is asked at these tiers: every later send of such a socket goes
  through `udp_sendmsg` with the peer as its address, so `sendmsg4` decides and refuses each one, and an approved
  connect would carry no datagram (`TestDatagramApprovalOnRealKernel`'s `udp6-mapped` cell); its unconnected datagrams
  are asked one destination at a time.
- *Not held:* a datagram in a `sendmmsg` batch is refused as before (a batch cannot be relayed whole, R13c's rules); a
  gate's ask range raised on an admitted UDP destination keeps gate.md R4's unsupported-completion refusal; a `tcp://`
  scope holds no datagram. `TestAskDatagramApprovalDenialAndRootCredit`, `TestAskDatagramApprovalCoversTheSocketOnly`,
  `TestAskDatagramRefusesWhatItCannotRelayBeforeAsking`, `TestAskUDPConnectIsHeldAndGranted`,
  `TestAskUDPConnectOfAnIPv6SocketToIPv4IsUnavailableAtRootTiers`; end to end `TestIntegrationAskUDPApproveDenyAndTimeout`
  (tier 1) and `TestRootAskUDP` (tiers 2 and 3).

**R15 — write-open record.** Notified when `flags & 0x243` is set, or `O_TMPFILE`. `CONTINUE`, save R15c's
refusal. An open with `O_PATH` set is a read whatever else it carries: the kernel drops the access mode, `O_CREAT`
and `O_TRUNC` from it, so neither R15c nor the write verdict applies (`decide.IsWriteOpen`). Advisory `verdict`: `allow` if the path falls under a `write` entry (nearest-ancestor, SEMANTICS §2), else
`refused`; `source: seccomp` marks it advisory (P0-DESIGN §4.3). At tier 1 a modification's verdict is the Landlock
ruleset's: `allow` when **any** write entry encloses the path, named by the nearest such entry, since Landlock
unions the rights of every rule on the path, so there a `deny_read` or implicit entry nested in a write entry
withholds no write right (nearest-ancestor would record `refused` for writes that happen: 52 of 768 actions on 6.17
in ADR 0016's grid). At tier 2 it is the root walk's (nearest entry wins, `decide.AdvisoryFS`, ADR 0028 S3), and
with no plane mode this loop refuses what that walk refuses itself (`fallbackMutation`, the amendment below). A read's verdict is decided by the
nearest write or `deny_read` entry, implicit entries being write guards that grant no read, and a `deny_read` the
ruleset leaves unenforced refuses nothing at tier 1 (tier 2's fanotify listener refuses it). The line names the
action as `compile --test` does, one label for both: an allowed read no `deny_read` decides, and a refused
modification, by the nearest entry of any kind, a `watch` entry included (SEMANTICS §7; a `watch` entry still decides
nothing), where the line said `unmatched`; a read tier 1 allows under a `deny_read` it cannot enforce by that entry
with the marker ` (unenforced: parent writable)`, which the line dropped (ADR 0017's `fs/read-watch` and
`fs/read-deny-read-nested-in-write` cells). *Amended 2026-10-25:* an `O_PATH` open beneath a
`deny_read` at tier 1 is `allow` by that entry with the marker ` (O_PATH: reads nothing)`, whether the ruleset
enforces the entry or not, since no `file_open` hook runs for one (`decide.AdvisoryFS`). *Amended 2026-10-25:* so is it at tier 2 and 3, where neither the fanotify listener nor the decision plane (whose only open hook is
`file_open`) sees one, and its line is this loop's there too (R7a's amendment). R15c's `deny_write`
refusals, R15d's and, at tier 2 with no plane mode, the fallback's mutation refusals (below) are made on top. At tier 2 the fanotify listener decides every open without seeing its access
mode, so a write-open (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_TMPFILE`, `creat`) under a `deny_read` that
no `write` entry with a longer path covers is refused there, whatever the Landlock union grants, and its advisory
verdict is `refused`, `reason: read-denied`, named by that `deny_read` (`decide.ListenerOpenRefused`, the
predicate `compile --test`'s tier-2 write column asks), never `allow` from the enclosing write entry for a write
the run refused. An unlink, rename, mkdir, symlink or link is no open, so the listener never decides it: at tier 2
its verdict is the root walk's, and with no plane mode this loop refuses it itself (below); at tier 1 the listener
rule does not apply and the Landlock union decides it. Landlock checks an unlink's `REMOVE_FILE`/`REMOVE_DIR` and a rename's `REFER` on the
**parent directory**, so at tiers 1 and 2 (at tier 2 once the root walk allows the path itself) the advisory
verdict of an unlink or rename is decided at `dirname(path)`: `allow` when a write entry encloses the directory above the path, else `refused` with the
operation's reason: with `write: [./out]` the final `rmdir out` of `rm -rf out` fails `EACCES` and is recorded
`refused`, as `compile --test` answers it (agent-contract R15). At tier 1 a read under an enforced `deny_read` is
`allow` when a declared exec entry lies strictly inside the target and covers the path — the file itself, or
anything beneath a directory entry — because the exec grant holds its own fd with `READ_FILE` (enforce-landlock R5,
I11 (1)); the rule is that exec entry (`decide.ExecReadGrant`, which `Evaluate`'s Landlock read arm
shares). Tier 2's listener refuses such a read, and its verdict is unchanged. A read the verdict would allow that
lies at or beneath the name the Landlock ruleset leaves out for a built-in `deny_read` row absent at compile
(`RuleTable.AbsentDenyRead`, `AbsentRow.At`) is `refused`, `read_denied`, named by the row, at every enforcing tier,
and so is the unrestricted exec of a binary there (`decide.AbsentRead`; *amended 2026-10-25*, ADR 0067 D3): the ruleset refuses it, and the line said `allow`, `unmatched`, for a read that never happened.
*Amended 2026-10-25 (ADR 0077):* at tier 1 a notified read open this loop continues and the ruleset then refuses (verdict `refused`, `read-denied`, not
`O_PATH`, not one this loop refused itself) carries `mechanism: landlock` on its line (`readMechanism`), under every
mode that notifies it: `record: full`, an `fs.ask_read` entry's unheld read, and `reason.reads: on`, whose filter
arm notifies every read open where nothing else does (enforce-landlock R16) and whose allowed reads get no line
under `summary` or `off` (`quietRead`, R21's rule for held reads). The line is written before the kernel answers,
from the path this loop read, with this R15's caveat. At tier 2 and 3 no line carries it: the read Landlock refuses
first never reaches the listener, and one only tier 2 refuses is the listener's line (R7a)
(`TestReasonReadsRefusedReadIsOneLine`, `TestReasonReadsAllowedReadsWriteNoLine`).

*Amended 2026-10-17 (ADR 0021 (5), ADR 0028 S3):* the fallback's mutation refusal. At tier
`cgroup` with no plane mode (`Options.PlaneAttrs` unset) the fanotify listener decides opens and execs only, so a
mutation Landlock's union grants beneath a `deny_read` nested in a write entry would run. This loop refuses it, with
R10's errno (`EACCES`), itself and best effort, before the kernel acts: every notified non-read, non-attribute
operation whose tier-2 verdict above is a refusal (`fallbackMutation`, `internal/runtime/supervisor/fs.go`) — a
write-open the listener rule refuses (`read-denied`), and a mkdir, rmdir, unlink, mknod, truncate, symlink, a link's
or rename's end that lands there, or any other mutation the root walk refuses, with the operation's reason; a walk
that failed other than as the task's own lookup fails (`EMFILE`, `ENOMEM`, `EIO`, `EXDEV`) is refused under
`path-unreliable` once the table has a `deny_read`. *Amended 2026-10-17:* a walk
that reached an object with no path in this process's view (`errOtherView`: a pipe or socket behind `/dev/stdout`,
an unlinked file, or a file linked elsewhere) is not refused here, whatever its spelling: `decideFS` keeps the
spelling's refusal on the line, or writes it `observed` under `path-unreliable`, never `allow`, and continues the
syscall. A nameless object's write-open must run, and a linked file this process cannot see by its path is reached,
with namespaces refused (E24), only by the pathname race R15c names (`TestFallbackMutationWalkFailures`). The
refusal is recorded `refused` and the line is this loop's (who owns the line, above). It holds against R15c's races only;
the plane and tier 3 decide on the inode. A read-open is the listener's own decision and a chmod no tier below the
plane decides (CAPABILITIES `fs.deny_chmod`), and where a plane mode decides the run, or at tier `landlock`, nothing
is refused here (`TestFallbackMutationLeavesOthersAlone`). `TestFallbackMutationConverges` drives thirty syscall
forms on x86-64 (twenty on arm64); with the refusal disabled twenty-eight of them fail. R15's earlier tier-2
wording, which left every write beneath such an entry and every non-open mutation to the Landlock union, predated
ADR 0021 (5) (built 2026-10-04) and is corrected here (ADR 0043 F11).

**R15d — a link or rename out of an unenforced `deny_read`, refused at tier 2.** At tier 2 a `deny_read` entry
nested in a write entry is enforced by the fanotify listener, which matches the path of each open, so
`link(secret/key, hl)`, `rename(secret/key, mv)` or `rename(secret/, notsecret/)` would give the file a name no entry
denies, readable with no refusal. At tier 2 this loop refuses (R10's errno) a `link*` whose old name, the
`AT_EMPTY_PATH` descriptor's file included, is at or beneath such an entry, and a `rename*` whose source is, or is
a directory above one, with both ends checked under `RENAME_EXCHANGE`, each end as spelled and where the task's
lookup lands (`agent.RuleTable.DenyReadMoveTarget`) — an end with no spelling, a relative name whose join is over
`PATH_MAX`, is still walked; recorded `refused` under the entry, reason
`write-`/`rename-outside-contract`. An end whose walk fails other than as the task's lookup fails is refused under
`rule: path-unreliable`, as R15c refuses it, once the table has such an entry. The match asks the table's index
(`decide.FSIndex.DenyReadMoveTarget`), a map lookup per component of the path and two binary searches, not a scan:
the .env scan can put 50,000 such entries in the table, and a scan held every link and rename 12-15 ms
(`TestDenyReadMoveTargetCostDoesNotGrowWithEntries`). It is the index R15c's `DenyWriteTarget` is asked through,
built over these entries instead of the targets; its answer is the scan's (`TestTargetIndexMatchesScan`). Best effort against the same races as R15c; tier 3 decides on the inode. At
tier 1 the entry refuses no read at all (compile warns `unenforced`), so nothing is refused here.

**R15f — name entries at tier 2 (ADR 0043 D1, D5, D7).**
The advisory verdict at tier 2 (`decide.AdvisoryFS`) refuses, after the walk allowed it,
an operation on a file a name entry covers as a `deny_read` entry at the file's own path refuses it: a write-open and a
read-open `read-denied`, as the fanotify listener refuses them, and a create, `mknod`, `symlink`, `truncate`, a link's
new name, either end of a rename and an unlink with the operation's reason, named per D8; a climb that cannot decide
within the walk's bound is refused `path-unresolved`. Without a plane mode `fallbackMutation` enforces those
mutation refusals (R10's errno). The object's kind comes from the syscall where it says it (`mkdir*`, `rmdir`,
`unlinkat(AT_REMOVEDIR)`, `O_DIRECTORY`, which `O_TMPFILE` carries: a directory, which no name entry decides) and, for
a rename's source and an exchange's destination, from an `fstatat` (not followed) of where the end's walk lands, made
only at tier 2 for a table with name entries; a stat that fails leaves the kind unknown and both a file's and a
directory's questions are asked (fail closed). A rename that moves a directory so that files beneath it leave a name
entry's coverage (D5: out of every scope, beneath a dependency directory, or taking a dependency directory's name) is
refused by this loop beside R15d (`decide.FSIndex.NameMoveRefused`, asked of both ends where the task's lookups land,
each direction under `RENAME_EXCHANGE`), recorded `refused` under the entry's rule, `rename-outside-contract`; an end
whose walk fails other than as the task's lookup fails is refused under `rule: path-unreliable`. Best effort against
R15c's races; a plane mode decides both on the dentries. A read-open of a directory named like a covered file without
`O_DIRECTORY` is taken for the listener's refusal and records no line under `record: full`, though the listener never
sees a directory open. A held open's completion (`fs.ask`, `fs.ask_read`, a gate-held open: `completeHeldAskOpen`)
opens the file outside any plane, so at tiers cgroup and bpflsm a held file a name entry covers is refused
`read-denied`, named per D8, whatever the access mode, before any person is asked and again once the answer came,
against the table then in force (ADR 0043 interface 2); an alternate a person names is refused when a declared name
entry covers it there, as a built-in `.env` name is at every tier. A held mutation's completion (`fs.ask`, ADR 0047:
`askMutation`) is made by this process outside any plane too, so at tiers cgroup and bpflsm a mutation that makes,
removes or moves a file at a name an entry covers (an unlink, a symlink's name, either name of a link, either name of a
file's rename), or moves a directory so that files leave an entry's coverage, is refused with the operation's reason,
named per D8, before any person is asked and again once the answer came; a `mkdir` or `rmdir` is no name entry's.
`nameMove`'s refusal is a floor, as R15d's is: no person is asked to lift it.

**R15b — every verdict is taken where the path lands.** R15's and R17's verdicts are first taken on
the spelling the target passed, and Landlock (and tier 2's listener) decides the continued syscall on the file or
directory that spelling reaches. A write through another spelling of a write entry — a `/proc/<pid>/fd/N` magic link
or `/dev/fd/N` alias of a descriptor under it, a symlink into it, a system symlink such as `/var/run` — ran while its
line read `refused`, and a read or a write through a symlink the contract does not declare, planted in a write entry
and pointing into a `deny_read` entry or out of every write entry, was refused while its line read `allow` (ADR
0017's `fs/read-through-undeclared-symlink-to-deny-read` and `link/write-open-outside-through-undeclared-symlink`).
So, before the syscall is continued and inside the same `ID_VALID` bracket as every `/proc` read (R2), every verdict
is taken again on where the path lands, walked the way the task's own lookup walks it (the walk of R16b): the file
itself for an open that follows its final component and finds it (a pathname ending in `/` follows a final
symlink whatever its flags say, as the kernel's lookup does: `open("lnk/", O_NOFOLLOW)` lands where `lnk` points), else the resolved parent joined with the final
component — the directory Landlock's create, remove and rename hooks decide on. A name-making end (`LookupParent`,
below) ending in `/` is not followed: `filename_parentat` strips the slash and the name is looked up in its directory
as it is (`lookup_one_qstr_excl`), so `mkdir("lnk/")` is `EEXIST`, an `rmdir`, an `unlink` and a `rename` onto it are
`ENOTDIR`, and Landlock's `rmdir` and `rename` hooks are asked at `lnk` in its own directory; such an end is its
directory's walk joined with the name, slash or not (*amended 2026-10-19*: it was walked whole, so with `out/lk -> ../b/sub` an `rmdir` of `out/lk/` was decided on `b/sub`
and its line read `refused, unmatched`, a refusal no mechanism made, one of `ro/lk/` with `ro/lk -> ../out/sub` read
`allow` where Landlock refuses it `EACCES`, and `compile --test` followed a dangling `out/dl/` to the target it takes as
made later while this loop's walk fell back to `out/dl`). That place is matched against the
entries at their resolved paths (`agent.FSRule.Resolved`), and the line carries that verdict and rule; the recorded
`path` stays the spelling the target passed (R6's join, cleaned lexically), except for an end whose pathname holds a
`..` component or ends in a `.` (`walkNamed`): the clean resolves `..` lexically, and after a symlink that names another file than the one the
lookup reaches (`out/lk/../e`, with `out/lk -> realbin/sub`, cleans to `out/e`, and the kernel removes
`out/realbin/e`), and it drops a final `.`, so `out/lk/.` cleans to the symlink `out/lk` while the kernel acts where
it leads; such an end's `path` or `path2` is the place where the physical walk landed the directory of its
final component (as `filename_parentat` looks it up), joined with that component as spelled (`lineName`; an exec
line's `path` is named so too, R16b). The final component is never followed for the name, whatever the syscall does
with it: `out/realbin/sub/../ln`, with `ln -> e`, names `out/realbin/ln`, as the spelling `out/realbin/ln` does, though
an open follows it to `out/realbin/e`; a final `.` or `..` has no name of its own, and such an end is named where the
whole walk lands. A final `.` or `..` is never a symlink, so a lookup resolves it physically whether the syscall follows
a final symlink or not: an `O_NOFOLLOW` open, an attribute change with `AT_SYMLINK_NOFOLLOW`, `lchown` and `lsetxattr`
of `out/lk/..` act on the directory above where `out/lk` leads, and are walked and decided there (*amended 2026-10-19*: such an end was not walked, so its verdict was the lexical
clean's, and an attribute change outside every write entry read `allow, rule fs.write[./out/]` while, with a plane
deciding the run, R15c's refusal of a target reached so was skipped). Only a syscall that makes, removes or renames a
name in its directory (`unlink*`, `rmdir`, `mkdir*`, `mknod*`, `symlink*`, both ends of a `rename*`, a `link*`'s new
name, a unix `bind`: `pathQuery.parent`) refuses a final `.` or `..` before a lookup of its own (`EEXIST`, `EBUSY`,
`EISDIR`, `EINVAL`, `ENOTEMPTY`), so such an end is not walked and keeps the spelling. Which lookup an end makes is
stated once, as one of the kernel's four (`agent.Lookup`): the whole path with a final symlink followed
(`LookupFollow`: an open, an exec, `chmod`, `truncate`, a `linkat` old name with `AT_SYMLINK_FOLLOW`); the same with a
dangling final symlink followed to the name an `O_CREAT` open makes (`LookupCreate`); the whole path with a final
symlink not followed (`LookupNoFollow`: `O_NOFOLLOW`, `O_CREAT|O_EXCL`, `AT_SYMLINK_NOFOLLOW`, `lchown`, `lsetxattr`,
and a `link*`'s old name without `AT_SYMLINK_FOLLOW`, which `filename_lookup` looks up whole, so its final `.` or `..`
is walked); and the name-making families above (`LookupParent`). Every handler builds each end's walk from its lookup
(`pathQuery.as`, `openLookup`, `followLookup`), and `compile --test` lands a row's end with the lookup of the syscall
the row stands for through the same constructor (`agent.ActionKind.Lookups`, `Land`; limits-check-doctor-cli R28), so
the run and compile ask one walk of one end; `TestEveryRowEndIsWalkedAsItsSyscall` drives each handler a row kind
stands for and holds the lookup it walks each end with to the row's (*amended 2026-10-19*: compile asked a `link*`'s old name as a name-making end, so `out/lk/.` was
evaluated at the symlink `out/lk`, `allow`, while this loop walked it where it leads and the kernel refused it
`EXDEV`). So a `..` the clean resolves as the kernel
does names what the spelling names, and one after a symlink names the file the syscall reached. The name is taken
from the walk that decides, as it passes the directory of the final component, never from another walk: the walk
the verdict, rule, R15c and R15d checks and gate read (`fsTarget`'s memo, one walk per end), the image walk for an
exec (`execImage.name`), and once an ask holds the open the pin's own walk, on whose object every later refusal is
decided (`askLineName`). Every decision of such an end is taken where it is named or where it lands, never on the
lexical clean, which names a file no mechanism decides on (*amended 2026-10-19*): R15c's and R15d's match takes the end by its name before its landing (`matchEnds`); a walk that
fails past the directory of the final component takes the verdict, and a gate scores the open, where that walk names
the end (`decideFS`, `landed`); an fs.ask scope with no held object is matched on the name; an exec is decided on its
line's name, and a loader's program on its walk's name (R16b); and an open held under `gate.completion: held` takes this loop's walk before the pin rather than being
decided as spelled (`heldDirect`), and its line names that walk's name when nothing was pinned. R15c matched the
lexical clean first, so an open of `out/lk/../.git/config`, with `out/lk -> ../b/sub`, was refused under the target
`out/.git/config` on a line naming `b/.git/config`, a file that rule never covered, where `compile --test` lands the
path on `b/.git/config` and answers it unmatched. An agent can move a symlink between two walks of one notification, and a name walked apart
from the decision named a file the verdict and rule were never taken on (*amended 2026-10-19*). Every such end is named so whatever its verdict: a refused rename's or link's
new name, which no decision walked, is walked for its name, once, and that walk is the end's. The walk is made before
the notification is answered (after the answer it has no task to vouch for it), and before any wait for a person, so
a refusal made after the wait names what was decided before it. One that did not reach the directory of the final
component, or cannot name it in this process's view, keeps the spelling; one that fails past it (a final symlink
looping, a target in another view) keeps the name. A symlink's target is no end and is never walked
(`TestFSLineNamesWhereADotDotSpellingLands`, `TestFSLineNameIsTheDecisionsWalk` with the tree changed after every
walk, `TestTheWalkNamesADotDotSpelling`, `TestRefusalLinesNameWhereADotDotSpellingLands` for the lines of the ask,
gate and held-open refusals, with the link moved during a person's wait and before the pin,
`TestKernelRecorderNamingOfADotDotSpelling` for the naming a kernel recorder's line takes, and
`TestIntegrationDotDotLineNamesTheFileItsVerdictWasTakenOn` at tier landlock). The walk and the kernel's own lookup of
the same name remain two lookups (the race R16b discloses): the line carries the verdict, rule and name of where the
walk landed. Each end of every notified fs syscall is resolved once, and the
answer is shared by R15c's and R15d's checks. The common case costs one lookup: when the place is reached from this
process's root through no symlink (`openat2` with `RESOLVE_NO_SYMLINKS` on the parent, `fstatat` on the final
name), it is the spelling itself; else one `openat2` from the task's root (`RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS`)
answers, and only a pathname with `..`, a trailing slash or a final `.` (which R6's spelling drops, and which
the walk, like the kernel's lookup, fails `ENOTDIR` after a non-directory), a magic link, a place on procfs or a final
symlink that lookup misses on takes the component walk (measured on the development machine: about 5-10 µs against 52 µs
for the walk of an 8-component path). Such a symlink is a dangling one, which an `O_CREAT` open follows, or one whose
body passes through procfs's `self` or `thread-self`, which name this process there: a link to
`/proc/self/task/<the task's tid>/../../../../d/f` misses here and lands on `d/f` for the task (*amended 2026-11-02*:
only an `O_CREAT` open's and `compile --test`'s were walked, so an open for writing through such a link was decided on
the link's own name and went past a `deny_write` on `d/f`; `TestFSTargetResolvesProcSelfAsTheTask`,
`TestIntegrationDenyWrite`). Both shortcuts rely on the task sharing this process's root and mount tree, which a
run's task does (a new mount or user namespace is refused, E24 of enforce-cgroup-observe). The first is not asked of
the kernel per notification either: a directory reached with no symlink (`openat2` with `RESOLVE_NO_SYMLINKS`, not on
procfs) is scanned once for the names of the symlinks in it and kept (the walk cache), and a path in it lands on its
spelling unless its final name is one of those and the syscall follows it (a directory of more than 256 entries is
kept unread, and a path in it that follows its final name costs one `fstatat` of it). The run's own tasks change a directory
entry only by a syscall the filter notifies (`rename*`, `unlink*`, `rmdir`, `symlink*`, `link*`), so each such
notification empties the cache before it is answered, and nothing is kept while such a syscall may still be about to
run (until its thread's next notification, or the thread is gone, a zombie, or asleep in another syscall, which
its `/proc` entries are read for at most once per 20 ms per thread, outside the lock every notification takes). A change
made outside the run, which nothing notifies, goes unseen for at most 100 ms (`walkCacheTTL`), after which the
directory is scanned again. A cache hit reads nothing of the task's, so it needs no `ID_VALID` either; a walk is
bracketed as before. Measured on the development machine (`BenchmarkNotificationRoundTripRealWalk`, a real tree 15 components
deep, the three builds interleaved): a read-open or write-open in a granted tree costs this loop 5-10 µs, against
13-26 µs walking each one and 5-8 µs before any allowed path was walked; in the 6.17 guest
(`TestIntegrationFastPathOps`, best of three) the round trip fell from 115-160 µs to 45-52 µs on a quiet host (49-66
µs before), a figure the host's load moves by a factor of two either way. The advisory verdict's own cost does not grow
with the entries: the tables and the table's index answer per path component (`TestAdvisoryCostDoesNotGrowWithEntries`). A walk that fails as the task's own lookup fails (`ENOENT`, `ENOTDIR`, `ELOOP`,
`ENAMETOOLONG`, `EACCES`, `EBADF`, `EINVAL`) keeps the spelling's verdict (for an end named by its walk, the verdict
where that walk named it, when it got that far), since the syscall reaches no decision
either; one that reaches a place whose path names another inode in this process's view (another mount tree) keeps a
refusal and records anything else `observed` under `rule: path-unreliable`, never `allow`, since the kernel may have
decided either way. What remains is the race of R16b — a symlink or descriptor swapped between the walk and the
kernel's own lookup — and the shapes the resolved-path match cannot see (a bind mount of a write entry elsewhere).
The first verdict, on the spelling, is matched against every entry under both its declared path and its resolved
one, not the declared path alone. A relative path is joined to the task's `/proc/<pid>/cwd`, which the kernel spells
canonically, so under a project reached through a symlink (the cwd a shell reports, a symlinked `$HOME`) the joined
path names no entry by its declared path alone: a write Landlock allowed in a write entry would be recorded `refused
write-outside-contract`, and a read Landlock refused under a `deny_read` entry `allow`, which no walk re-takes
(`TestAPathIsMatchedUnderBothSpellingsOfAnEntry`, `TestIntegrationSymlinkedProjectIsRecordedAsTheKernelDecided`).

**R15e — a read the `deny_read` snapshot refuses, refused here (2026-10-26).** At tier landlock an enforced
`deny_read` grants the names beside each ancestor of its target from one listing at launch (enforce-landlock R3,
E10), so a name made there later, and everything beneath it, has no rule: Landlock refuses a read or an exec of it
all run while the contract's paths allow it. `Options.DenyReadSnapshot` (the tier-1 handle's `Snapshot.Refuses`, on
the landed path) says so; a read-capable open the verdict allows that it refuses is answered `EACCES` here, before
an ask, a held completion or a gate, with a `refused` line, `read-denied`, rule `deny-read-snapshot`; an exec whose
image it refuses likewise; a held read's deputy `EACCES` it explains is recorded the same way. It only ever adds a
refusal the kernel makes anyway, and every doubt (an unstatable component, an overlayfs file named at launch with a
new inode) leaves the open to the kernel and its line to the verdict (ADR 0069's 2026-10-26 note).

**R15c — the built-in `deny_write` set, refused here.** Where a kernel decision plane decides the run, the checks
below are early refusals and recording backed by the plane. At tier landlock and on tier cgroup's listener they are
the targets' only refusal, best effort against the races below, which compile discloses per target and run_start
records as `best_effort` `deny_write/default` (ADR 0041 D1 (a)); a contract that says `fs.assurance: kernel` is
refused before the child starts there instead (enforce-landlock R5a). Beneath a write entry Landlock grants
the entry's rights over the whole subtree, so no ruleset can refuse a write to a target of the built-in `deny_write`
set (agent-contract R20: git hooks and config, harness settings, shell startup files), and tier 2 decides writes
with the same ruleset. This loop refuses it instead: a notified modification — a write-open or `creat`, `unlink*`
and x86-64's `rmdir`, `mkdir*`, `mknod*` (a regular file, FIFO, socket or device node), `symlink*` (the created link), `link*` (the new name, and the old one, since a
second name for a file inside a target is a path to it no target spells; for `linkat`'s `AT_EMPTY_PATH` form, whose
old name is empty, the file its descriptor holds, read from `/proc/<pid>/fd/<olddirfd>`: that is how an `O_TMPFILE`
written in the worktree becomes a named hook) and `rename*` (both ends, each also as a
directory above a target, since a rename moves whatever lies beneath it: renaming `.git` away, writing a hook, and
renaming it back, or `RENAME_EXCHANGE` of a prepared directory into `.git`) — that reaches a target is answered with
R10's errno by this loop, not `CONTINUE`d, and recorded `refused`, `rule: fs.deny_write[<target>]`, `reason` the
operation's own (`write-`/`delete-`/`rename-`/`mkdir-outside-contract`). That line is written whatever else the
arguments hid — another end that could not be read, or is empty — and under `record: off` too, since the agent got
the errno (REASON-CHANNEL §1), a link whose old name was empty or unreadable included. Each end
is matched as its line names it (its spelling; for an end R15b names by its walk, a `..` or a final `.`, the walk's
name, never the lexical clean: *amended 2026-10-19*) and, when that
matches nothing, again where the task's own lookup lands (R15b's walk, inside the same `ID_VALID` bracket): a
symlink into a target, a `/proc/<pid>/fd` magic link to one, and a dangling final symlink an `O_CREAT` open follows
to create its target — the walk follows it as the kernel does, where it used to stop at the link's own name.
Targets are matched at their declared and their resolved paths by `agent.RuleTable.DenyWriteTarget`, the predicate
`Evaluate` answers `compile --test` with, asked here through the table's index (`decide.FSIndex.DenyWriteTarget`,
R15d's index over the targets): the same target, the lowest-positioned match, for a map lookup per component of the
path and two binary searches, where the scan walked every target for each end of every notified modification (9.5 ms
a question against 50,000; `TestDenyWriteTargetCostDoesNotGrowWithEntries`). A table with a target spelled unclean
is asked by scan. A read of a target, and every modification that reaches none, keeps its
verdict and is continued; an observe run records the refusal it would make as `observed` and continues it (R30). The
walk is paid for every modification of a run whose set is not empty. In such a run a modification is a decision
kind, so one whose pathname this loop cannot read whole fails closed as R5 fails a connect: R10's errno, `refused`
under `rule: args-unreadable` when nothing of it was read (a `NULL` pointer, an unmapped or `PROT_NONE` page, a target
this process may not read) or `rule: path-truncated` when the read stopped before its NUL or when a relative name
read whole joins its cwd or dirfd to more than `PATH_MAX` (the kernel resolves it with no limit on the total, so it
lands where this loop has no spelling), `reason` the operation's
own, under `record: off` too. So does one whose spelling matches no target and whose walk fails other than as the
task's own lookup fails (R15b's list): `EMFILE`, `ENFILE`, `ENOMEM` or `EIO` in this process, or `EXDEV`, refused
under `rule: path-unreliable`, since where it lands is unknown and may be a target; continued, an agent that pushed
this process toward fd exhaustion had its write go wherever the kernel's lookup led
(`TestDenyWriteRefusesAPathItCannotWalk`). A walk that reaches a file with no path in this process's view (a pipe
behind `/dev/stdout`, an unlinked file behind `/proc/self/fd/N`) reached nothing a target names and keeps the verdict. Continued as R5's record-only path, it would go wherever the kernel's own read of
the name led: at tier 1 a target that calls
`prctl(PR_SET_DUMPABLE, 0)` denies this unprivileged process every `process_vm_readv` (the ptrace access check),
and its hook write then landed under a line reading `observed` (reproduced on 6.17 by `TestIntegrationDenyWrite`).
A name the kernel cannot read either costs nothing, since its own answer is `EFAULT` or `ENAMETOOLONG`; the cost is
that at tier 1 a non-dumpable process (`ssh-agent` makes itself one) may modify nothing the filter notifies, where
the tier-2 supervisor, holding `CAP_SYS_PTRACE`, reads it and decides as usual. **Best effort, not a closure:** the
kernel reads the pathname again, and resolves it again, after this loop continues a write it decided lands
elsewhere. A sibling thread or `CLONE_VM` child that rewrites the string in the target's memory between the two
reads needs no filesystem write at all, and defeats the `AT_EMPTY_PATH` reading as well: an old name read as `""`,
so taken from the descriptor, then made `.git/config` before the kernel copies it. (A name this loop cannot read but
the kernel can — a page made `PROT_NONE` only while this loop reads it, or a `VM_PFNMAP` mapping that
`process_vm_readv` refuses and the task's own access does not — is refused as above, not continued.) A peer that swaps a symlink or a directory on the way
between the two lookups (R16b's race) lands the write in a target under a line that reads `allow`; a hard link to a
target made before the run is a name no target spells, and so is another case of a target's name on a
case-insensitive file system (vfat, exFAT, NTFS, a casefold directory of ext4, F2FS or tmpfs: `.GIT/hooks/pre-commit`
is `.git/hooks/pre-commit` there, while targets and landings are matched by string, and neither the spelling
shortcuts nor the walk fold case); a bind mount of a target elsewhere is not matched (R15b);
the socket inode a unix `bind(2)` creates (a mknod the filter cannot see); and `chmod(2)` (notified under
`record: full` or an `fs.write` gate, and refused here only where a decision plane decides the run, R17), like
extended attributes and `chown(2)` (notified under an `fs.write` gate only, and refused here likewise only under a
plane, R17), and `utimensat(2)`, never notified, is not refused here at all. A `truncate(2)`, notified from Landlock ABI 3, is refused like an `O_TRUNC`
write-open when it reaches a target. The required race-free enforcement is the kernel decision plane's nearest-wins walk (SEMANTICS
§2), using `lsm`/`fmod_ret` at tier cgroup or `lsm` at bpflsm. `TestDenyWriteRefusedBySupervisor`,
`TestDenyWriteReadAndObserve`, `TestDenyWriteRefusesAnUnreadablePath` and `TestFSTargetLandsWhereTheKernelWrites` pin it, and `TestIntegrationDenyWrite` on
the real kernel under `record: summary` and `record: off` (an `O_TMPFILE` linked in as a hook by descriptor and
through `/proc/self/fd`, a second name for `.git/config` by descriptor, a hook written directly, a regular file and a
FIFO made as hooks by `mknod(2)`).

*Amended 2026-10-25 ([ADR 0071](../adr/0071-user-deny-write.md)):* a contract's own `fs.deny_write` entries are in the
same set (`RuleTable.DenyWrite`, `BuiltIn` false) and are refused here the same way, on the copied pathname as spelled
and where the task's lookup lands, under the rule `fs.deny_write[<entry as declared>]` (FSRule.RuleName names it; no
code of this loop tells the two kinds apart): blocked for ordinary commands; not race-free at the no-root tier, where
run_start lists the cell `fs.deny_write`. The predicate is nearest wins for such an entry: a write entry strictly
beneath it reopens its subtree, so a modification there is continued under that write entry, while a rename of a
directory above the entry is still refused (decide.FSIndex answers it with one upward walk,
`TestUserDenyWriteIndexMatchesScan`). A hard link to a file entry made before the run is a name no entry spells and is
continued here, as for a built-in target; the plane's inode row refuses it. `TestUserDenyWriteRefusedBySupervisor` and
`TestIntegrationUserDenyWriteAtLandlock` pin it. The reopening write entry's own name is the entry's: a
rename of it at either end is refused (the rename question), and so is a modification that makes the name, asked of
`DenyWriteNameTarget` (`makesName`: a mkdir, a symlink, an `O_CREAT|O_EXCL` open, which a mknod is recorded as, and a
link's new name, its second end); an unlink or rmdir of it and a write-open of it are the write entry's, so an
`O_CREAT` open that makes it anew after a removal is continued here, where a plane refuses it.

**R16 — execve argv.** Read via `process_vm_readv`: pointer array (≤8192 entries) then each NUL-terminated string up
to the remaining 128 KiB budget (R3); exhausting it sets `argv_truncated: true`. It is read only for an exec that
writes a line: the verdict never depends on it, so under `record: off` every exec but a refusal — an allowed one, a
PATH-search candidate, or one observed because its pathname is unreadable under a contract with no `exec:` section —
reads none and writes no line (and a miss, R16b (0), reads none and writes no line at any record level) (`TestExecQuietReadsNoArgv`, `TestExecRecordOffUnreadablePathWritesNothing`). `path` is the `execve` pathname
resolved via R6 when relative; when R6 cannot name it (its join to the cwd or `execveat` descriptor passes
`PATH_MAX`, or the cwd or descriptor cannot be read) and the walk (R16b) reached a file in this process's view,
`path` is that file, where the exec lands, rather than an empty or relative name. `script`/`stage` are not populated here (§11). The verdict and the answer are R16b's:
an exec matched to a grant — an entry naming the binary, a directory entry above where it lands, or the inode an entry
named reached at that entry's resolved path (a hard link of it is refused, R16b) —
is `allow` and `CONTINUE`d (Landlock's `EXECUTE` bit decides it on the inode); a PATH-search candidate → `observed`
(R28); otherwise `refused`, `exec-not-allowed`, refused by this loop — except under a contract with **no** `exec:`
section (SEMANTICS §1, "deny nothing"), where the Landlock builder adds `EXECUTE` to every read set: there an exec no
entry names is `allow`, `rule: unmatched`, and only the exec open is refused, as the read it is — an undeclared
binary under a `deny_read` tier 1 enforces (not one R4 leaves unenforced) is `refused`, `read-denied`, named by that
entry, which is `decide.Evaluate`'s Landlock arm; the `deny_read` is matched where the exec lands when the walk
reached a named image: the kernel's spelling of it, whether or not this loop could walk that spelling back to the same
inode, so a binary there run through `/proc/self/fd/<n>` after the agent made its directory unsearchable is refused
`read-denied` as the kernel refuses it, not recorded `allow` on the descriptor's spelling (*amended 2026-10-17*). An allowed exec whose resolved path
is a declared `mcp[].command[0]` and whose `argv[1:]` equals that server's declared arguments also records an `mcp`
event (`rule: mcp[<name>]`, `transport: stdio`, the argv as `command`): P0's minimum MCP producer (P0-DESIGN §2.2).
Matching the path alone would name a server for every other use of a shared runner such as `npx`. The image the walk
reached is matched first, when it is the file `command[0]` named when the loop first saw it, by inode and resolved
path both, as R16b matches a file entry's grant (so another name of the same inode, a hard link or another mount, is
not the server), and then the exec line's name (R15b, R16b), which the same walk gave (*amended 2026-10-19*: a start spelled `./tools/../tools/mcpsrv`, or as the link's target,
wrote no `mcp` line; a name from a second walk
wrote an `mcp` line for the agent's own image).

*Amended 2026-10-06 ([ADR 0048](../adr/0048-exec-command-rules.md) (3)):* in a run whose table has exec command rules, every exec reads its names and argv[0], `record: off` included (*amended 2026-11-01:* an exec whose argv[0] was not read, unreadable or past the budget, is refused `args-unreadable`, `TestExecCommandUnreadableArgv0IsNotUnguarded`), and an exec no interpretation guards reads nothing more; a guarded exec reads as much argv as its decision needs, in stages: a prefix (32 elements, 8 KiB) up to the located subcommand, then the whole vector within this rule's budget only when the decision can still change. Pointers are read up to 1024 per call and strings in batches of up to 1024 `process_vm_readv` segments of up to 256 bytes (never crossing a page), a longer string completed on its own. An exec whose verdict depends on argv past the budget is refused `args-unreadable`; one decided on what was read is never refused for its length (`git add` of 10,000 paths under `allow: [git add]`). So `TestExecQuietReadsNoArgv` reads: no argv beyond what a command rule or a gate needs (`TestExecCommandUnguardedReadsArgv0Only`, `TestExecCommandStagedRead`).

**R16b — the exec decision.** Every exec is decided here, on the file it
names, before it is answered; none is `CONTINUE`d on a verdict this loop could not make good.

*Amended 2026-10-06 (ADR 0048 (3)):* after the image floor and before the gate, an exec the floor allows and whose walk reached an image is decided by the command rules (`decide.ExecCommand`): a deny or ask match, or a constrained tool's unlisted invocation, is refused here with `EACCES` and never continued (R); an allow is continued, a copied fact (D, the cell `exec.rules/argv`). A lookup that failed keeps its own errno, and a PATH-search candidate is never asked about (`TestExecCommandKeepsLookupErrno`). *Amended 2026-10-06:* in a run with command rules no exec is continued unless its walk reached an image the rules then decided: an exec whose walk failed, or whose pathname could not be read, is answered by the loop itself, never continued, since the kernel's own lookup could reach a file the walk did not (a symlink renamed into place between the two). A failure the task's own lookup would meet keeps its errno (EFAULT for a pathname whose read faults before its NUL, ENAMETOOLONG for one with no NUL in its first PATH_MAX bytes, as the kernel's getname answers; *amended 2026-10-06:* a pathname cut at PATH_MAX was answered EFAULT; *amended 2026-10-06:* the change holds for every run with an `exec:` section, with or without command rules, `TestExecPathnamePastPathMaxEveryRun`) and is observed under the decision's rule (*amended 2026-10-16:* an `ENOENT` or `ENOTDIR` walk is a miss, (0) below, answered with its errno and written as no line); any other (EMFILE, ENOMEM, EXDEV) is refused `path-unreliable`, EACCES (`TestExecCommandNeverContinuesUnwalked`, `TestIntegrationExecRuleLinkRaceTier1`). In a run with command rules every image's first 256 bytes are read by reopening the walk's own `O_PATH` descriptor through `/proc/self/fd` (an identity check confirms the inode), each `#!` interpreter is walked as the task walks it, and a failed interpreter walk answers that walk's errno under rule `interpreter-unresolved` (`TestExecCommandShebang`). *Amended 2026-10-06:* the header was read only where a rule named an interpreter, but any ruled tool can be a `#!` interpreter, which the kernel loads inside the same execve with no notification of its own (`#!/usr/bin/rm -rf` ran under `deny: [rm -r]`). It is read for every exec of such a run, and an image whose bytes cannot be read (or whose interpreter's cannot) is refused `image-unreadable`, EACCES (`TestExecCommandShebangAnyRuledTool`, `TestIntegrationExecRuleShebangInterpreter`). *Amended 2026-10-06 (ADR 0048):* the head is read only of a file the kernel's `do_open_execat` would open for the task. One it is sure to refuse with EACCES before reading a byte (no execute bit, a `noexec` mount or procfs or sysfs, or permission bits that give the task's filesystem ids none, read from `/proc/<tid>/status` only when the bits differ between classes) is that lookup's EACCES, observed, and never opened (`execRefused`); where the answer depends on what is not read (CAP_DAC_OVERRIDE, an access ACL) the head is read as before. A root supervisor otherwise read files the task could not run, and its errno (ENOENT, ELOOP against EACCES) told the task whether one starts with a `#!` line (`TestExecImageRefusesWhatTheKernelRefuses`, `TestIntegrationExecRuleNotExecutable`). *Amended 2026-10-06 (ADR 0048, third):* a dynamic loader run as a command (`ld-linux-x86-64.so.2 /usr/bin/rm -rf tree`) maps its program and jumps to it with no execve of the program's own, so that program is decided here as the exec's image: the loader's vector (the exec's argv, or for a script whose last `#!` interpreter is a loader the vector binfmt_script gives it) is read as glibc's and musl's loaders read it (`execmatch.LoaderProgram`), the operand walked from the task's cwd, and the program read by the operand's name, its walked image's name and its identity, with the argv the loader gives it (`command_via: loader`). A loader is known by a loader's basename (requested, walked, or as a `#!` line names it) or by the identity of one of the host's loaders that compile lists, never by its ELF type, which a static-pie program shares while taking its first word as an operand. A program that cannot be read as the loader will (an option neither loader has, an operand with no `/`, which glibc searches library paths for, a walk that fails, an operand that is itself a loader) is refused `loader-unresolved`, and in a run whose images are restricted a program no `exec.allow` entry grants is refused `loader-program-unmatched`, both EACCES; in a deny-list run (images unrestricted) a program, or an image, that lies in the run's own `CODEX_HOME` grant is refused `codex-home-exec`, EACCES, judged where the walk landed (*amended 2026-10-16*, agent-contract.md R10a; `TestDenyListRefusesExecFromTheCodexHome`) (`TestExecCommandLoaderProgram`, `TestExecCommandLoaderRestricted`, `TestIntegrationExecRuleLoader`). Command rules disable the fast handover until the exec is decided, as an exec gate does (`TestExecCommandDeny`, `TestExecCommandAllowList`, `TestExecCommandAsk`).

*Amended 2026-10-19 ([ADR 0048](../adr/0048-exec-command-rules.md) (3) P2, K3):* in a run whose decision plane pins its execs (`Options.ExecPinner`, set only for a run whose slot Prepare pinned; never in an observe run), every exec this loop continues carries a pin, written after the decision and the `ID_VALID` that closes it and immediately before `CONTINUE`: the image's identity as the plane holds it (fdinfo's `ino` and its mount's device from mountinfo, the walk reads it when asked, `pathQuery.kid`), its final name, the `bprm->filename` alloc_bprm spells, the form and `#!` chain the command rules read (every exec of such a run is walked, a lineless one too), and the argv elements the decision read (the whole vector under an exec gate; a script's whole mapped vector, read to the 128 KiB bound and refused if its decided elements changed). An exec whose pin cannot be built or written is refused here, rule `exec.pin`, `pin_unavailable: true`, `EACCES`, with a line under `record: off` too; a full pin map is swept once of the pins whose thread is gone (its `/proc` start time differs or it is gone) (`TestExecPinWrittenBeforeContinue`, `TestExecPinUnavailableRefuses`, `TestExecPinScriptCoversTheMappedVector`, `TestExecPinGateAloneIsUnknownForm`). *Amended 2026-10-19 (K4):* a pinned exec's line is the kernel's (the recorder folds its exec record with the plane's held or kill sample, ADR 0048 (8)), so this loop hands its naming over and writes no line for a continued one; when no kernel recorder reads the run (`Options.KernelExecHandoff` false) a kill would have no line, and the exec is refused `exec.pin`, `pin_unavailable`, instead (`TestExecPinRefusedWithoutAKernelLine`). The MCP start line of an exec whose line the kernel owns is the recorder's, written after the exec's own and, in a pinned run, only once the plane held it.

*Amended 2026-10-25 ([ADR 0064](../adr/0064-harness-hook-exec-grant.md)):* the harness hook's exec grant is the one exec
grant the runtime adds to the table this loop decides on: under an allow-list contract whose own rules do not admit a
provisioned hook, an image rule for the tego binary and a runtime command rule that admits the hook's exact argv, both
`exec.harness-hook[<tego binary>]` (agent-contract R10a (5)). The agent's exec of the binary is decided here as any
exec is: the image floor matches it to that rule, and the command rule admits the whole vector equal to the hook's,
argv[0] included, and refuses every other (`tego run`, `tego approve`, `__probe`, another hook or reason path, no
argument) `exec-not-allowed` under the same rule, so the shell sees exit 126. The open deputy's Landlock grant of the
same inode (enforce-landlock R5) admits nothing here: it is the domain's, for the child stage, and no exec rule names
it. At tier landlock the vector decided is this loop's copy (ADR 0048 R5); where the plane pins execs, the decision
read the whole vector and the pin covers it (`TestIntegrationHarnessHookGrantIsTheExactArgv`, under a plain allow-list
and under `gate.completion: held`).

*The walk.* What the exec names is resolved the way the task's own lookup resolves it, one component at a time from
the task's root (`/proc/<tid>/root`) for an absolute pathname or its cwd or `execveat` descriptor for a relative
one: every symlink is read and followed (an absolute target from the task's root; `MAXSYMLINKS`, 40, then `ELOOP`),
`..` at the task's root stays there, procfs's `self` and `thread-self` — which name the *caller*, so resolved by
this process would be this process — are read at a procfs root as the task's thread group and thread (only in this
process's own procfs instance; another's pid numbers cannot be translated, `EXDEV`), and every other procfs symlink
is a magic link the kernel follows from the pid directory it sits in. So `/proc/self/fd/N`, `/dev/fd/N`, a symlink
the agent made to either, `/proc/self/task/<tid>/fd/N`, `/proc/<tgid>/fd/N` from another thread and a dirfd-relative
name all reach the descriptor they name for the task. `execveat(AT_EMPTY_PATH)` names the image by descriptor only
when the pathname is empty (`getname_flags` with `LOOKUP_EMPTY`): a non-empty pathname is walked as usual, so a
descriptor of a granted binary beside a pathname naming a memfd is decided on the memfd. The walk reads
`/proc/<tid>` and is inside the notification's `ID_VALID` bracket (R2, E3); it runs with this process's credentials,
so a path the task could not search can resolve here — which can only make an `allow` optimistic (the kernel then
refuses), never a refusal false. *Amended 2026-10-16:* where this process's lookups pass
directories the task's cannot (it holds `CAP_DAC_OVERRIDE` or `CAP_DAC_READ_SEARCH`: root at tiers cgroup and
bpflsm), the walk of an exec's own pathname (`walkImage`) holds the task's search permission to every directory it
looks a component up in, `.` and `..` included, as `link_path_walk`'s `may_lookup` does: the owner's class by the
owner bits, the group's by the filesystem gid or a supplementary group, the others' otherwise, then
`CAP_DAC_OVERRIDE` or `CAP_DAC_READ_SEARCH`, read from `/proc/<tid>/status` once per walk. A directory the task is
sure not to be able to search ends the walk with `EACCES` there, the kernel's own answer, whatever lies below it; a
directory whose answer is not sure (an access ACL, a filesystem whose permission operation is its own: FUSE, NFS,
SMB, Ceph, procfs, and any filesystem outside a closed list, below; a task holding a
DAC capability in another user namespace; credentials that cannot be read)
turns a failed walk's lookup errno into `EACCES` and leaves a walk that reached a file as it was. Without it a miss
(0) answered from root's walk told the task whether a name exists in a directory it cannot search (a root-owned 0700
directory: 126 for a present file, 127 for an absent one, in five of six plane cells that had answered 126 for both),
and a refusal carrying the walk's errno (an unreachable script's missing interpreter, `ENOENT`, against the kernel's
`EACCES`) told it what such a script's `#!` line names. At tier landlock the supervisor runs with the agent's own
credentials, its own lookups are refused where the task's are, and no check is made (`TestExecImageHoldsTheTaskToSearchPermission`,
`TestSearchCheckedMeansTheSupervisorBypassesDAC`, `TestPlaneExecSearchOracle`). *Rejected:* answering every exec
under a directory the check is unsure of with `EACCES` (an ACL that grants the task would then refuse an exec the
kernel runs); checking only after a miss (the directories' descriptors are gone by then, and the interpreter case
is no miss); `setfsuid`/`setgroups` on a walker thread with the task's credentials (a Go thread whose credentials
differ from its siblings', for every exec, and still no answer for the task's capabilities in its own namespace).
*Residual:* a mandatory access control module (AppArmor, SELinux) that refuses the task a directory the mode bits
open is not read, so there the walk still answers as if the task could search.
*Amended 2026-10-16:* the check goes on past an unsure directory, so a directory further down that
the task is sure not to search still ends the walk with `EACCES` (it stopped at the first unsure one, and a 0700
directory under an ACL'd one was walked through). A walk that reaches a file through an unsure step says so
(`execImage.unsure`), and nothing read from that file then changes the task's errno: a `#!` interpreter walk of the
chain that fails is answered `EACCES` under `interpreter-unresolved`, never its own `ENOENT`, which told the task that
a script in a directory whose ACL denies it names a missing interpreter (`TestExecImageHoldsTheTaskToSearchPermission`'s
access-ACL cases, `TestExecMissKeepsEveryRefusal`). The cost is a script reached through an ACL that grants the task,
whose missing interpreter is answered 126 where the kernel answers 127. *Amended 2026-10-16:* a
procfs magic link of a process other than the task's own thread group is an unsure step, at every tier, whether or
not the search check runs. The kernel follows one for the task only when `ptrace_may_access(PTRACE_MODE_READ_FSCREDS)`
lets the task at that process (`proc_fd_access_allowed`), which this process cannot decide (Landlock's ptrace
scoping, Yama and the other LSMs answer it; dumpability changes), while its own rights let it follow a link the task
cannot: root at tiers cgroup and bpflsm, and at tier landlock a process outside the agent's Landlock
domain. A miss behind such a link was answered `ENOENT` with no line, so `/proc/<pid>/cwd/present` exited 126 and
`/proc/<pid>/cwd/absent` 127 for a directory the agent cannot list, at every tier. A walk through one that fails is
now `EACCES`, decided and recorded as an attempt; a walk that reaches a file is decided as before, its errno guarded as
above. The task's own links are followed as before (`ownMagicDir`: `/proc/<tgid>`, any of its threads'
`/proc/<tgid>/task/<tid>`, and their `fd` and `ns` directories, compared by descriptor, which `/proc/self`,
`/proc/thread-self` and `/dev/fd` lead to); `map_files`, whose lookup also needs `CAP_CHECKPOINT_RESTORE`, is never
the task's own (`TestExecImageMagicLinksOfAnotherProcessAreUnsure`, `TestIntegrationExecMagicLinkOracle`,
`TestPlaneExecMagicLinkOracle`). *Rejected:* `EACCES` for every such link (it refused the exec of a granted file
through a run process's descriptor that the kernel lets the task follow, and recorded a memfd reached that way by its
spelling instead of as fileless); reading `ptrace_may_access`'s credential and dumpability rules (the LSMs stay
unread, so the answer is still not sure). *Amended 2026-10-16:* the task's own links include those
in a non-leader thread's top-level `/proc/<tid>` (a pid directory of its own, which readdir hides, another inode than
`/proc/<tgid>/task/<tid>`) and in the `task/<tid>` entries beneath it. They were unsure, so a miss behind such a
thread's `cwd` was answered `EACCES` with a refusal line where the kernel answers `ENOENT`. A thread's top-level
directory is known by the `Tgid` line of the `status` file read through it (`ownMagicDir`;
`TestExecImageMagicLinksOfAnotherProcessAreUnsure`).
*Amended 2026-10-16:* two directories the check answered sure are unsure. (a) A directory on a
filesystem whose server or daemon decides each lookup by the caller's credentials (FUSE without `default_permissions`,
NFS, SMB, Ceph) is unsure whatever its mode bits, and so is one whose filesystem type cannot be read. The check
answered a 0755 directory there sure before it asked which filesystem it was on, while the server can refuse the task
a directory it lets root or the squashed uid search (an NFSv4 ACL, which `system.posix_acl_access` does not show; a
FUSE daemon that decides by uid), so a root walk's miss there told the task whether a name exists in it
(`TestExecImageServerFSDirectoriesAreUnsure`). The cost, at tiers cgroup and bpflsm only: a failed walk through such a
directory is `EACCES`, which is no miss, so the exec is decided as any failed walk is, and what that costs depends on
who answers it (*amended 2026-10-16:* this said a refusal line and 126 for every run).
Where the supervisor decides the run's execs (an `exec:` section on the fanotify listener, or under a decision plane
with command rules or an exec gate), the loop answers `EACCES`: refused `unmatched` with a refusal line, observed
under its entry for a candidate of the run's own `PATH` search (R28), observed in a run with command rules. So a
`PATH` directory on NFS or FUSE turns an `execvp` caller's misses there back into lines, and a command found nowhere
reads 126 rather than 127 to such a caller (a shell's own `PATH` search stats each candidate and makes no such exec).
Everywhere else the kernel answers with its own errno (127 for an absent name): a decision plane with no command
rules, no exec gate and no MCP relay (*amended 2026-11-01*: a relay's gate decides here, ADR 0126 §4) takes the exec
through the fast handover, and the kernel recorder writes the failed syscall
as it writes every failed exec there, with its `syscall_ret`; otherwise a spelling a granted entry matches, and any
exec under a contract with no `exec:` section, is continued under an `allow` line naming a path that names nothing
(the noise (0) removed, back for such a directory) (`TestExecUnsureWalkPerRunShape`). (b) At every tier, a procfs
directory of a process other than the task's own thread group, its pid directory or any directory beneath it, is an
unsure step, as
its magic links are (`procForeign`). Its 0555 bits say nothing: the permission operation of `/proc/<pid>/fdinfo` asks
`ptrace_may_access`, which the task fails for a root process of another user and for any process outside its Landlock
domain, and a pid directory under `hidepid` asks whether the caller may see the process, while this process's own
rights let it in. A miss in another process's `fdinfo` was answered `ENOENT` with no line where the kernel answers
`EACCES`, so the agent learned which descriptors that process holds open (`/proc/<pid>/fdinfo/0` 126,
`/proc/<pid>/fdinfo/<absent>` 127): at tier landlock for any process of its user outside the run, at the root tiers
for root's. Procfs directories that belong to no process (`/proc` itself, `/proc/sys`) and the task's own thread
group's (a non-leader thread's top-level `/proc/<tid>` included) stay sure; a directory is placed by climbing `..` to
the one below the procfs root, at most 8 levels, and reading the `Tgid` line of that one's `status` file, which only a
pid directory has (`TestExecImageProcDirsOfAnotherProcessAreUnsure`, `TestIntegrationExecProcDirOracle`,
`TestPlaneExecProcDirOracle`). *Residual:* under `hidepid=invisible` the kernel answers `ENOENT` for another user's
pid directory while the walk reaches it, so `/proc/<pid>` itself, or a file in it, is decided (126) where the kernel
answers 127; whether a pid exists is no secret (`kill(pid, 0)` answers `ESRCH` or `EPERM`). *Rejected:* adding procfs
to (a)'s list (every walk through `/proc/self`, `/dev/fd` or the task's own descriptors would be unsure, and a miss
behind them `EACCES`); disclosing (a) as a residual beside the MAC one (the walk can say it is not sure and fail
closed, so it does).
*Amended 2026-10-16:* (a)'s list was open. The filesystems it named were unsure and
every other one was read by its mode bits, while kAFS (`afs_permission` asks the cell with the caller's key and
refuses a directory lookup without `AFS_ACE_LOOKUP` before `generic_permission`), 9p mounted `access=user` (the server
walks with a per-uid attach), Coda (`coda_permission` asks venus as the caller) and eCryptfs (its permission operation
asks the lower inode as the caller, and the lower may lie on any of these) decide by the caller too. A 0755 directory
there that the server refuses the agent was walked through at the root tiers, so an absent name was a miss (127, no
line) and a present one was decided (126), where the kernel answers `EACCES` for both. (a) is now a closed list the
other way round (`modeBitsFS`): a directory is read by its bits only on a filesystem whose permission operation, for
`MAY_EXEC` on a directory, is `generic_permission` over the mode bits, owner and group `fstat` reads and the access
ACL the walk asks about. Those are ext2/3/4, xfs, btrfs, f2fs, tmpfs, ramfs, overlayfs (its second check runs with the
mounter's credentials, the same for every caller), squashfs, erofs, isofs, vfat and msdos, exfat, udf, sysfs and both
cgroup hierarchies (kernfs), debugfs and autofs, each read from the kernel source. Procfs keeps its own reading ((b),
and bits that deny are unsure). Every other directory is unsure whatever its bits: the servers' filesystems above,
ntfs3 (whose `noacsrules` lets every caller in), ZFS (out of tree, so its permission operation is not read here) and
any filesystem the list does not name (`TestExecImageServerFSDirectoriesAreUnsure` holds kAFS, 9p, Coda, eCryptfs,
ZFS and an unknown type unsure, and each listed type sure). The cost is (a)'s, on more filesystems: at tiers cgroup and
bpflsm a failed walk through a directory outside the list is `EACCES`, decided as (a) says for each run shape, so a
`PATH` on ZFS or on a 9p share leaves lines for an `execvp` caller's misses there where the supervisor decides the
run's execs. A filesystem shown to answer from its bits alone can join the list. *Residual:* the list is read from
the kernel source, not measured: no AFS, 9p, Coda or ZFS ran here, and on a listed filesystem a mandatory access
control module stays what the walk does not read. *Rejected:* adding kAFS, 9p and Coda to (a)'s list of servers
(another open list: the next filesystem that decides by the caller would be read by its bits again); every directory
unsure (a miss under `/usr/local/bin` on ext4 would be a line again in every root-tier run).
*Amended 2026-10-27 (ADR 0048 C8):* where no search check is made (tier
landlock), the walk of an exec's own absolute pathname, a `#!` interpreter's or a loader's program's, one that follows
its final symlink and that the walk does not name (no `..` component and no final `.` as spelled), is first asked of
the kernel (`lookupInOne`): `openat2` from the task's root with `RESOLVE_CACHED|RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS`,
the RCU walk alone, which mounts no automount point (on 5.14 `RESOLVE_NO_XDEV` alone mounts one before it refuses
`EXDEV`); only where that reaches a file, the answering `openat2` with `RESOLVE_NO_XDEV` in place of `RESOLVE_CACHED`
(no mount point crossed, so every component lies on the root's mount and no `self` is resolved as this process); then
the file's `fstatfs`, which leaves a procfs root to the walk. Every failure, crossed mount, magic link or doubt is left
to the walk above, whose errno, automount point, unsure step and name are the answer as before
(`TestLookupInOneIsTheComponentWalks` compares both, name included, over symlinks, loops, `..`, procfs paths and
mount crossings with a task that is another process; `TestLookupInOneNeverMountsAnAutomountPoint`,
`TestLookupInOneResolvesFromTheTasksRoot` and `TestLookupInOneLeavesAProcfsRootToTheComponentWalk` as root, in the
KVM run). In a run with command rules the task's root is opened once per exec (`taskRoot`): the exec's own walk opens
it inside its `ID_VALID` bracket, its interpreters' and a loader's program's walks start from it, and `recordExec`
closes it when the decision ends (`TestExecHeldRootClosedAfterEachExec`). No answer changes.

*The decision*, in order, on the file the walk reached:

0. A **pathname that names nothing** (*added 2026-10-16*): the walk of a non-empty pathname met `ENOENT` (a component
   or the final name does not exist, a symlink leads nowhere) or `ENOTDIR` (a component is no directory, an
   `execveat` descriptor that is no directory). The exec cannot happen, so nothing is decided: the loop answers that
   errno itself (`missedExec`), never continues it, and writes **no line at any record level**, no `exec` line and
   no `refused` mirror; `run_end.supervisor.exec_missing` counts it. This comes before every arm below, in every
   run, with or without an `exec:` section, command rules or an exec gate, and before the fast handover of a run
   with neither, which used to continue it. Answered rather than continued, a file created at the path after the
   walk is a later syscall's, decided then: there is no race to disclose. Where a kernel recorder follows the run's
   execs the loop leaves the supervisor-owned marker every exec it decides leaves (`ExecNaming.SupervisorOwned`), so
   the kernel's sample of the failed syscall is dropped too. The answer is no refusal (`respMiss`): an observe run
   answers the errno too, where R30 continues every refusal. The kernel would answer the same errno, so an observe
   run still enforces nothing, while a continued miss is a second lookup that a file renamed into place after the
   walk wins: an exec that runs with no line, its kernel record dropped by the marker (*amended 2026-10-16:* the miss was continued under observe, and an agent swapping a script in and out of place by rename
   while it ran it 400 times ran 44 of 129 execs with no line of any kind at tier landlock, and 22 to 32 of about 100
   in each plane mode). *Why:* `execvp` makes one `execve` per `PATH` directory, so one program started by name
   wrote a refused line per directory in a restricted run (`unmatched`), an observed one in a run with command rules
   or for an R28 candidate, and an allowed one in a run with no `exec:` section; in one test agent seven tries
   of `git push` made 133 refused exec lines, and `drift` read `exec[bash]` as 25 allowed and 300 observed for 25
   starts. The record now holds what the agent did. *What is not a miss:* only the exec's own pathname is read
   this way. A path that names something keeps its decision and line exactly as before, so no refusal is weakened:
   a file no entry grants (`unmatched`), a command rule's refusal, a candidate that holds a file (R28), a `#!` script
   whose interpreter is missing (`interpreter-unresolved`, its `ENOENT`), a loader whose program is missing
   (`loader-unresolved`), an image whose head cannot be read (`image-unreadable`), a walk that failed otherwise
   (`ELOOP`, `EACCES`, `EMFILE`, `EXDEV`), an empty pathname and an unreadable one. *Rejected:* one `observed` line
   per miss at `record: full` only (R12: the record level gates bodies, never events, and the line would still be
   counted as an action by drift and measure); collapsing a search into its start (needs state across
   notifications, R28's argument); keeping the refused line and teaching every reader to skip it (each reader would
   have to tell a miss from a refusal of a file that exists, which the line does not say). *Who misses:* only a task
   that can search every directory on the way; at a root tier the walk holds the task's search permission (*the
   walk* above, *amended 2026-10-16), so a name under a directory the task cannot search is
   answered `EACCES`, the kernel's answer, present or absent, and is no miss. The residual this rule first stated
   (that such an existence answer predated it) was wrong: with no `exec:` section, or a restricted one under a
   kernel plane, the exec was handed to the kernel, which answered `EACCES` for both. *Amended 2026-10-16:* and only through links the task may follow: a walk through another process's procfs magic link
   that fails is `EACCES`, no miss (*the walk* above). A walk that failed looking a name up at an automount point is
   no miss either (`automountLookup`): the walk opens each component `O_PATH` as a final lookup, so the kernel's
   `follow_automount` does not mount an idle automount point whose dentry is positive (a direct or systemd autofs
   mount point, an `S_AUTOMOUNT` stub) that it meets (no `LOOKUP_PARENT`, `LOOKUP_DIRECTORY`, `LOOKUP_OPEN` or
   `LOOKUP_AUTOMOUNT`), and the next name is missing there, where the kernel's own walk mounts it and finds the file.
   *Amended 2026-10-16:* an automount point is an autofs directory (its flag is on
   the dentry) or any inode its filesystem marked `S_AUTOMOUNT`, which `statx` reports as `STATX_ATTR_AUTOMOUNT`: NFS
   crossmnt and referral submounts (a stub with no lookup operation, where the walk's next lookup fails `ENOTDIR`),
   CIFS DFS links, FUSE submounts, AFS mountpoints and debugfs's `tracing`. Only autofs was recognised, so an exec of
   an existing program under an idle NFSv4 submount was answered `ENOTDIR` and written nowhere, where before this rule
   it was continued or recorded; in the 6.17 guest a fresh debugfs's `tracing/README` was a miss (`ENOENT`, no line)
   while the kernel's own lookup finds the file and answers `EACCES`. Such an exec keeps its errno and is decided as
   before this rule: continued under a contract with no `exec:` section or a granted spelling, handed to the kernel
   where a decision plane takes the run's execs (the fast handover, which the plane decides on the file the kernel
   loads: in the guest the kernel mounts tracefs and answers `EACCES`), refused with the errno otherwise, and recorded
   (`TestExecImageAutofsFailureIsNoMiss`, `TestExecAutofsFailureIsContinuedWhereItWas`,
   `TestExecImageAutomountPointFailureIsNoMiss`, `TestPlaneExecAutomountIsNoMiss`). *Amended 2026-10-17:* a `..` step that fails at an automount point is no miss either. A
   stub with no lookup operation (an NFS crossmnt or referral submount) fails every lookup that starts from it, `..`
   included, with `ENOTDIR`, so `sub/../tool` through an idle stub was a miss with no line, where the kernel's walk
   mounts the submount as an intermediate component, climbs back out of it and finds the tool. At tiers cgroup and
   bpflsm the search check had already made such a walk unsure (NFS and CIFS lie outside `modeBitsFS`) and answered it
   `EACCES`; at tier landlock nothing did (`TestExecImageDotDotOutOfAnAutomountStubIsNoMiss`, the stub stood in for: no
   NFS server ran). And what the walk does not mount is a *positive* automount point only: an indirect autofs map's key
   is a negative dentry, which `follow_automount` mounts on any lookup, so the walk's own lookup asks the automounter
   for it, as root at the root tiers, reaches what lies beneath and misses nothing there. *Residual:* the walk goes on
   past a directory whose search answer it is not sure of (*the walk* above), so it can ask for an indirect key's mount
   that the task's own lookup, refused higher up, would not have asked for; the automounter mounts only what its map
   names, and the task's answer is the one *the walk* gives. *Rejected:* triggering the mount of a positive automount
   point from the walk (a root supervisor would mount filesystems for an exec it then refuses). Tests of (0):
   (`TestExecMissWritesNoLine`,
   `TestExecMissKeepsEveryRefusal`, `TestExecMissUnderKernelRecorder`, `TestExecMissObserveAnswersErrno`,
   `TestIntegrationExecMissWritesNoLine`, `TestIntegrationExecMissObserveRace`, `TestPlaneExecMissWritesNoLine`,
   `TestPlaneExecMissObserveRace`).
1. An **anonymous image** — no link count (a memfd is created unlinked; so is a file unlinked since it was opened),
   or a descriptor the kernel spells `/memfd:…` or without a leading `/` (`anon_inode:[…]`) — is `refused`,
   `exec-not-allowed`, `rule: exec-anon`, `fileless: true`, with `refusalErrno`. It comes before any name is
   matched: a memfd's name is the agent's to choose and may hold `/` and `..`, so no spelling, a PATH-search
   candidate's included, can admit one; and the recorded `path` is the raw readlink with only ` (deleted)` removed,
   never cleaned into a disk path. Under a contract with no `exec:` section it is `allow` (deny nothing).
   *Amended 2026-10-17:* it also comes before the fast handover of a run
   whose execs a decision plane decides (no exec gate, no command rules): the walk has classified the image when the
   handover is chosen, and an anonymous image handed over was refused by the plane's `bprm_check`, whose sample names
   no entry, so the line said `unmatched` with no `fileless` where tier 1's says `exec-anon`, and `compile --test`'s
   `bpflsm` column, which answers `exec-anon`, disagreed with the run. An image the run admits (`exec.anonymous: true`,
   or no `exec:` section) is still handed over (`TestExecAnonymousImageIsRefusedBeforeTheHandoff`).
2. A **grant** — the spelling names an entry; or the file is the inode an entry named
   when the loop first saw it (`StatID`, symlinks followed, exactly as the Landlock builder opens the entry to bind
   `EXECUTE`), or lies under a directory entry's resolved path — is `allow` and `CONTINUE`d. A directory entry, and a
   file entry the loop could stat when it first saw it, is matched by where the walk landed (`execImage.link` when
   `here`), under the entry's own name, and by the spelling only when the walk reached no file in this process's
   view *and* failed as the task's own lookup would (`ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG`, `EACCES`,
   `EBADF`, `EFAULT`: `execLookupFailure`). A walk that failed otherwise — `EMFILE`/`ENFILE`/`ENOMEM`/`EIO` in this
   process, which an agent can push it toward, or `EXDEV` — never verified the spelling and matches no grant: it
   falls to (5) under `path-unreliable` (`TestExecWalkFailsOtherThanLookup`). R6's spelling is cleaned lexically and the kernel
   resolves `..` physically, so `/grant/link/../x`, with `link` a symlink out of `/grant`, spells `/grant/x` and runs
   a file Landlock's `EXECUTE` on `/grant` (or on an entry `/grant/x`) refuses; its line, and the naming a kernel
   recorder's line takes, name what the pathname reaches as an fs line names a `..` end (R15b): where the image walk
   itself landed the directory of the final component, joined with that component as spelled (`execImage.name`, never
   a second walk), never `/grant/x`, and never the target of a final symlink (`/usr/lib/../bin/npx` names
   `/usr/bin/npx`, not the `npx-cli.js` it runs; `TestExecLineNamesWhereADotDotSpellingLands`,
   `TestExecLineNameIsTheImagesWalk`). A declared MCP server's start is matched first on the image itself: the file its
   `command[0]` named when the loop first saw it, by inode and resolved path both, as a file entry's grant matches, so
   another name of the same inode is not the server; then on that name (`mcpServerOf`, `mcpIDs`;
   `TestExecOfADeclaredMCPServerByAnotherSpellingEmitsMCP`, `TestIntegrationMCPStartThroughADotDotSpelling`). That is
   how a granted
   binary reached by its resolved path, a symlink to it, or its own descriptor (a regular-file `fexecve`) is
   recorded as the grant it is. Entry identities are taken once, when a policy carrying the entry
   first reaches the loop (before the agent runs), and kept for the run like `resolveUnixEntries`.
   *Amended 2026-10-17:* a directory entry grants an image beneath its resolved path
   only while that path still holds the directory the loop stat'ed then (`dirHeld`), the inode the Landlock builder
   bound `EXECUTE` to. The rule moves with the inode: after `mv out/bin out/old; mkdir out/bin` inside a write entry
   the kernel refuses an exec of `out/bin/tool` (`EACCES`), which the line recorded `allow exec[./out/bin/]`; such an
   exec now falls to (5), `refused`, answered by this loop. A directory that cannot be stat'ed now grants nothing; an
   entry the loop could not stat when it first saw it keeps its path match (`TestExecLineFollowsTheHeldDirectory`, the
   conformance cell `refer/exec-in-recreated-exec-name`).
   A file matches a file entry by its inode *and* its resolved path: the entry's inode (`StatID`) and its
   symlink-resolved path are both taken when the loop first sees it, and the image must be that inode reached at
   that path in this process's view (`execImage.here`, `link` equal to the entry's resolved path). The inode alone
   would admit every **hard link** of a granted binary: on Ubuntu 25.10 `/usr/bin/{sleep,echo,env,ls,dd,ln,mv,…}`
   are hard links of one uutils multi-call binary, and `exec.allow: [/usr/bin/sleep]` would record `allow
   exec[/usr/bin/sleep] /usr/bin/ls`, which `compile --test` and tier 2 (both matching by path) answer `refused`. A
   hard link is another name of the inode, not a spelling of the entry: it falls to (5), `refused`, answered by
   this loop. Landlock still allows `EXECUTE` on the inode (enforce-landlock R5), so this refusal is tier 1's guard
   for the case. The path check alone would not do: a file swapped in at the entry's resolved path after the loop
   was built is a different inode, and the inode check keeps refusing it. A descriptor is decided on the spelling
   it was opened by (its `/proc/self/fd` link), so an `fexecve` of a hard link's descriptor is refused as the hard
   link is. (`TestExecHardLinkOfGrantedBinaryIsRefused` here and in `internal/cli`.) A granted image is admitted by
   its file only when it is reachable **in the supervisor's own mount view** at the entry's resolved path
   (`execImage.here`, `internal/runtime/supervisor/exec.go` `execGranted`). An agent that reaches a granted binary
   from another mount view — through a `bwrap` or `chroot` bind, or a mount namespace of its own in which the path
   lies elsewhere — does not match the entry by inode alone: unless the path it passed names the entry itself (the
   first arm), the exec is `refused`, answered by this loop. That is what tier 2 answers too, whose listener
   matches the path it reads in its own view, and what `compile --test` answers, so the three agree.
3. A **PATH-search candidate** (R28) is `observed`, `path_search: true`, answered with its lookup's own errno —
   `refusalErrno` where it holds something no entry grants (where the directory holds no such name, the common case,
   it is a miss, (0), and writes no line since 2026-10-16). A
   pathname with a `..` component is never a candidate: R6 cleans it lexically into one while the kernel resolves
   it physically, so `/usr/local/bin/link/../python3`, with `link` a symlink the agent made, would be recorded as
   the search's probe of a file that lies elsewhere; it falls to (4) or (5).
4. With **no `exec:` section**, the R16 `deny_read` arm, answered by this loop; everything else `allow`.
5. **Anything else** is `refused`, `exec-not-allowed`, `rule: unmatched` (or `args-unreadable` when the pathname
   could not be read, `path-unreliable` when the descriptor could not be or the walk failed other than as the
   task's lookup would), answered by this loop: `refusalErrno`,
   or the lookup's own `ELOOP`/`ENAMETOOLONG`/`EBADF` when there was nothing there to run (an `ENOENT` or `ENOTDIR`
   walk is a miss, (0), answered with that errno before this list), so a caller that tests for `ENOENT` keeps
   working. A directly-invoked ELF loader that is not itself an entry lands
   here: it holds `EXECUTE` as some binary's `PT_INTERP`, so Landlock would have run it.

At tier 2 the fanotify listener decides the exec's open of its image as it decides every open (enforce-cgroup-observe
R8): an image under a `deny_read` that no longer `write` entry reopens is refused there (`EPERM`), whatever the exec
entries and Landlock grant — an `exec.allow` directory inside a `deny_read`, a contract with no `exec:` section. Such
an exec is still `CONTINUE`d, and its line reads `refused`, `read-denied`, under that `deny_read`
(`decide.ListenerOpenRefused` on where the image lies), not `allow` under the exec entry (ADR 0017's
`exec/exec-entry-directory-inside-deny-read`). At tier 1 nothing refuses that open.

The pair are decision kinds (R5): a handler that cannot finish refuses. An observe run continues everything and
records `observed` (R30). A refused exec line is true by construction; a continued one is decided by Landlock on the
inode the grant was matched on. Two record-v1 optional additions on the exec payload carry what the walk saw: `fileless` (rule 1's image) and `dropped` — a linked image whose place lies under a write entry at its
resolved path and whose inode's ctime is after the loop was built, allowed or refused alike. The place is the
kernel's spelling of the image, whether or not this loop could walk that spelling back to the same inode (the
`deny_read` and `codex-home-exec` arms' `imageWhere`): a binary the run wrote, run through `/proc/self/fd/<n>` after
the agent made its directory unsearchable, is flagged as the same binary run by its path is (*amended 2026-10-17*: the flag was judged only on a confirmed spelling, so the agent could strip it at will). An
unconfirmed spelling that was a removed name another hard link outlives is judged without its ` (deleted)` marker;
its unlink changed its ctime, so it is flagged when that name lay under a write entry. The images an exec loads
beyond its own are judged the same way where this loop walks them, which is in a run with command rules (ADR 0048
(3)): each `#!` interpreter of the chain and a directly-invoked loader's program, the file the loader maps and jumps
to (*amended 2026-10-17*: `ld-linux-x86-64.so.2 /work/proj/tool` was flagged on the loader's
image only, so the agent could strip the flag by naming its binary as the loader's operand). That walk is a fact of
every exec whose own walk reached an image and that has a line, whatever the image floor answers: an exec the floor
refuses, and an observe run's would-be refusal, which runs, are walked as an allowed one is, and the command rules
still decide only an exec the floor allows (*amended 2026-10-17*: the walk lived inside the
command decision, so an observe run's would-be refusal ran a binary it wrote with no flag). Of an exec the floor did
not allow only the walk is made, with no staged argv read or match for a guarded tool, and one with no line (no exec
gate, `record: off`, not a refusal: a `PATH`-search candidate, an observed exec) is not walked, `dropped` being read
by a line only (*amended 2026-10-19*: such an exec paid the whole staged read and match, thrown
away, and its line read argv again). `dropped` is judged once per exec, and every
owner of its line copies that one value: this loop's line, the naming a kernel recorder's line takes when a run with
command rules or an exec gate hands the decided exec over (R7a), and the fast handover's naming
(the kernel's copy was a second expression no test reached). In a run without
command rules neither is walked, and `dropped` judges the exec's own image only: a binary the run wrote, run as a
loader's operand or named by a `#!` line, carries no flag there, and a file an interpreter reads as its script
(`sh /work/proj/x.sh`) is never an image. Walking every exec's chain and loader operand in every run is the command
rules' cost, rejected for a flag that only adds to what a line says.
`dropped` is decided on ctime, so a file another process changed there during the run reads the same; it needs no
join of fs and exec lines. Surfacing either in `drift` is that package's (owned there).

*The race this walk does not close.* The walk and the kernel's own lookup after `CONTINUE` are two lookups, and two
things can change between them. A **descriptor** the walk read can be swapped by any thread of the process or any
`CLONE_FILES` child (they share the descriptor table). A **path** — a symlink on the way to the image — can be
repointed by *any* concurrent process able to write that directory, not only a thread of the agent: another process
in the run, or one outside it with access to the path. Either has the kernel load another image than the one decided
on, a memfd included, which Landlock then allows. This is inherent to deciding an fd- or path-keyed syscall from a
seccomp notification; only a run with no concurrency on the descriptor and no writable path to the image is free of
it. So the supervisor's own anonymous-image refusal and the direct-loader refusal are **best-effort in tiers 1 and 2,
not closures**: a raced exec's line reads `allow` for the file the walk reached, never `refused` for one that ran,
but the image that ran is not the one recorded. Tier 3's `bprm_check_security` decides on the file being loaded and
is the race-free enforcement (SEMANTICS §4, GAPS C30, condition B1).

*The `memfd_create` closure, which does not wait for the walk.* The main anonymous-image vector — a memfd —
is closed race-free in tiers 1 and 2 at *creation*, not by the walk, on every supported kernel. `memfd_create`'s
number and flags are scalars in registers, immutable once the syscall traps, so the tier-1 seccomp filter (which
tier 2 inherits, enforce-landlock.md R13) decides it (enforce-landlock.md R11a): where the kernel honours
`MFD_NOEXEC_SEAL` it refuses with
`-EACCES` any `memfd_create` that does not set `MFD_NOEXEC_SEAL` or that sets `MFD_HUGETLB` (hugetlbfs does not
enforce the `F_SEAL_EXEC` the flag sets), and on a kernel without the flag, where no flag makes a memfd
non-executable, it refuses every `memfd_create` with `-ENOSYS`. A probe, not the version, decides which: most
kernels below 6.3 lack the flag, and RHEL 9.8's 5.14 backports it and gets the sealing arm. Either way no
executable anonymous image is created inside the run. An arm is
installed only when the run restricts exec; a contract may opt out with `exec: {anonymous: true}`, which drops the
arm, reports `exec.deny` `false` on the run's capability line at tier 1 (at tier 2 only once the cgroup handle's
`Capabilities` narrows that row by the inherited tier-1 handle's, which it does not yet: the tier-2 line still reads
`true` for such a run) and makes the supervisor allow an anonymous image
(still recorded `fileless`) rather than refuse it — the walk becomes only the record then. The supervisor's
anonymous-image refusal is therefore the record and the best-effort backstop for images that arrive by another
route (a descriptor received over `SCM_RIGHTS` or inherited at launch, a file unlinked after opening), never the
sole guard against the memfd vector. The refused `memfd_create` leaves no ledger line, like the other filter errno
arms (the terminal-injection ioctls, MPTCP): nothing ran, and the agent sees the errno. Whatever the kernel, a run
that restricts exec gets an arm (the refusing arm where `MFD_NOEXEC_SEAL` is unknown), and the sealing arm refuses
a hugetlb memfd even with the flag; `TestIntegrationExecDecisions` runs whichever arm this kernel gets, and
`TestIntegrationExecWalkBackstop` runs the walk with no arm on every kernel.

**R17 — unlink/rename/mkdir/symlink record.** `CONTINUE`, save R15c's refusal. Rename reads both `path` and `path2` (each via
R6); advisory `verdict` from the same match as R15, taken at both ends as Landlock takes it: the source's parent, the
destination's parent (the right to make the entry there, and `REFER` across directories), and `REFER`'s rule that a
file moved across directories gains no right the entries over its source did not grant (`decide.RenameGainedBy` and
`decide.ReferRefuses`, the rule `compile --test`'s rename answers by; both ways under `RENAME_EXCHANGE`). A source that is refused names the
line; otherwise a refused destination does, so a rename out of a write entry is `refused` under the destination's
entry or `unmatched`, where the source alone recorded `allow` for a rename the kernel refused (ADR 0017's
`fs/rename-out-of-write-entry`). A `link*` is decided the same way at its new name. Each end is walked (R15b).
*Amended 2026-10-17:* a `link*` is decided as Landlock's
`hook_path_link` decides it, at both ends' directories: `MAKE_REG` on the new name's directory and, when the two
directories differ, `REFER` on both (`decide.AdvisoryFS` asks a link of the parent directory, as it asks an unlink or a
rename), never on the file itself, so a file-level write entry, which grants no directory right (the Landlock builder
masks it to file rights), gets no second name in another directory; then `REFER`'s no-gain rule compares the file
rights the ruleset grants at the new name's directory with the file's own (`decide.LinkGainsBy`, Landlock's
`no_more_access`), across directories only. Both no-gain rules, a rename's and a link's, count what the ruleset grants
rather than the entries' declared bits (a write entry's rights with the read set, `EXECUTE` while images are
unrestricted, `IOCTL_DEV` only under `/dev`, and each exec grant's `EXECUTE|READ_FILE`), so a link or a rename into an
`exec.allow` directory inside a write entry, where the file would gain `EXECUTE`, is `refused`. Before, the line said
`allow` for both while the kernel answered `EXDEV`: a line that was not what the mechanism answered (ADR 0016). The
syscall is still continued, so the refusal and its errno stay Landlock's (`TestLinkLineIsWhatLandlockAnswers`, the
conformance fixture `refer` on the kernel). At tier 2's plane modes and at tier 3 the recorder explains the chain's
`EXDEV` by the same rules (enforce-cgroup-observe R9).
*Amended 2026-10-17:* a rename's no-gain rule is asked as Landlock's
`hook_path_rename` asks it (`decide.RenameGainedBy`): a rename within one directory reparents nothing and is not
compared; across directories the rights the ruleset grants at the new name's directory are compared with the moved
object's own (its directory's and its own rule's), never with a rule on the name it replaces, both ways under
`RENAME_EXCHANGE`; and only the file rights count for an object that is no directory. A gain of directory rights alone,
which no compiled table can produce (every write entry carries the whole write set), is resolved by an `fstatat` of the
moved object, not followed; one that cannot be read is compared as a directory. Before, the line compared the two
names themselves, so the atomic replace of an `exec.allow` file entry inside a write entry (`mv out/tool.new
out/tool`), which Landlock allows, was recorded `refused`, `rename-outside-contract`, while the syscall went through
(`TestLinkLineIsWhatLandlockAnswers`, the conformance cells `refer/rename-onto-exec-file-entry*`).
*Amended 2026-10-17:* the no-gain rule asks where the inodes the Landlock
builder granted are now, not their declared names. The builder binds each exec grant to the inode it held at Prepare,
and the rule moves with it: an `exec.allow` directory renamed within a write entry takes its `EXECUTE` to its new name,
and a fresh directory made at the declared name has none. So the exec grants' rights at an end are those of the
inodes the loop held when it first saw the entries (`decide.HoldExecGrants`, the same identities as R16b's), matched
against the end and each of its directories by `fstatat` with the final component not followed
(`decide.HeldExecGrants.Grants`); an end that cannot be stat'ed all the way is answered by the declared names. Before,
after `mv out/bin out/old` a rename or a link into `out/old` was recorded `allow` while the kernel answered `EXDEV`,
and after `mkdir out/bin` a move out of `out/old` into it `refused` while the file moved
(`TestReferLineFollowsTheHeldInode`, the conformance cells `refer/*-moved-exec-*` and `refer/*-recreated-exec-*`).
And an end is the name the syscall acts on: `rename(2)` and `linkat(2)` without `AT_SYMLINK_FOLLOW` never follow a
final symlink, so an end that is a symlink fs entry's own name (`fs.write: [./out/cur]`, `out/cur -> bin/v1`) is the
symlink, in its own directory, where Landlock has no rule (its rule is on the target's inode); the end was
canonicalized to the target, so the atomic swap of such a symlink (`mv out/cur.new out/cur`) and a move onto it were
recorded `refused` while the kernel allowed them, and a link or a move of the symlink into an `exec.allow` directory
`allow` while the kernel answered `EXDEV` (`TestLinkLineIsWhatLandlockAnswers` rows A to D, the conformance cells
`refer/*symlink*`). The syscall is still continued, so the errno stays Landlock's.
`truncate(2)`, notified from Landlock ABI 3 (enforce-landlock R11), is recorded `op: truncate` with a modification's
verdict — `TRUNCATE` is a write right — and R15c's refusal; the mode-change family (`chmod`, `fchmod`, `fchmodat`,
`fchmodat2`), notified under `record: full` and, under an `fs.write` gate, at every record level (enforce-landlock
R11), is recorded `op: chmod`, `allow` unless that gate refuses it (scored as an `fs.write` by `gateFS`, authority
`gate`, `fs-gate`), named as a modification of that path,
which is right: no Landlock ABI has a chmod right, and the plane's `path_chmod` (enforce-plane step B) refuses one beneath a
`deny_write` target only (`fs.deny_chmod` stays unclaimed at every tier), so the line says what happened under the
entry a tier-3 run would decide it by, save the refusal below. `fchmod` and an empty `AT_EMPTY_PATH` pathname name the
file the descriptor holds. Before, both left no line at tier 1 or tier 2 (ADR 0017's truncate and chmod cells).
Where a decision plane mode decides the run (`Options.PlaneAttrs`, TIER3-PLAN T13), its `path_chmod` refuses a mode
change beneath a built-in `deny_write` target in the kernel (enforce-plane R12), so this loop refuses such a chmod
itself by R15c's predicate, `EACCES` and one `refused` line, rather than record an `allow` the kernel then overturns
(`TestChmodUnderThePlaneRefusesADenyWriteTarget`). *Amended 2026-10-16 (ADR 0041 Step 2):* under an `fs.write` gate the xattr family (`setxattr`, `lsetxattr`, `fsetxattr`, `removexattr`,
`lremovexattr`, `fremovexattr`, and 6.13's `setxattrat` and `removexattrat`) and the `chown` family (`chown`, `lchown`,
`fchown`, `fchownat`) are notified at every record level too and handled as a chmod is (`recordAttr`): recorded
`op: xattr` or `op: chown`, `allow` unless the gate refuses it as an `fs.write` of the file it lands on, and refused
beneath a `deny_write` target where a plane mode decides the run, whose `path_chown` and xattr hooks refuse it there. A
POSIX ACL is the extended attribute `system.posix_acl_access` (or `_default`), and setting one rewrites the mode bits as
a chmod does, so a gate that refused `chmod 755 ../outside/f` let `setfacl -m u::rwx,g::r-x,o::r-x ../outside/f` make
the same change with no score and no line; a `chown` hands the group bits to another group. Every attribute name is
scored, not only the ACL ones, and the name is never read: a sibling thread could rewrite it between this loop's read
and the kernel's. The f- forms, and `AT_EMPTY_PATH` with an empty pathname (or a NULL one for the *xattrat forms, the
kernel's `getname_maybe_null`), name the file the descriptor holds. Timestamps (`utimensat`, `utimes`, `futimesat`,
`utime`) stay unnotified: they change no permission and no content, and `tar x` sets one per file, so a write gate
would cost every extraction a round trip per file for a change no gate predicate is about
(`TestWriteGateScoresAnAttributeChange`, `TestWriteGateNotifiesXattrAndChown`).

**R18 — response shapes.** Exactly three: (a) `CONTINUE` for every record-only path and R13b's admitted datagram; (b) `errno`
(`error=-E*,val=-1`: `-EACCES`, R10's errno; `-EPERM` for the mount family, R31; the run's own kernel program's
errno for an addressed datagram it refuses, R13b) for refused connects/Fast-Open-sends (batched ones included, R13c)/unix-connects, for any send whose
address this tier cannot match (R4, E4, R13b) — on every socket type, connected or not, and for `sendmmsg` any
message up to the kernel's `UIO_MAXIOV` clamp — for a datagram carrying an address the `models[]` guard refuses,
or an admitted one this loop cannot relay whole, and for every addressed batch on an IP socket under that guard (R7,
R13b), for an allowed connect or Fast-Open send past the relay
ceiling (R21), and for an admitted unix connect whose resolved socket nothing admits or that this loop could not
make as the task (R11: `unmatched`, `path-unreliable`, `relay-credentials`; R11a: `unix-foreign`,
`unix-origin-unread`, `unix-bind-unrecorded`), for a datagram to a name under a write entry that names nothing (R11a:
`unix-absent`, answered with its lookup's errno, not `-EACCES`), for a relayed send carrying
`MSG_ZEROCOPY` (R7: `zerocopy`), and for a modification that reaches a built-in `deny_write` target, or whose
pathname cannot be read whole in a run with such a target (R15c); (c) relayed real result (`error=0,val=0` /
`error=-EINPROGRESS,val=-1` / real errno) for allowed connects and Fast-Open sends (R9, R12), for an admitted
datagram on an IP socket under the `models[]` guard (R7), and for a unix walk that
failed as the task's own lookup would (R11).

**R19 — target death mid-notification.** `ID_VALID`/`NOTIF_SEND` returning `-ENOENT` means the id is stale (thread
died before the response) — not an error: abandon the `notif`, no retry, no response attempt, loop to `NOTIF_RECV`.
No event for a decision never reached (E1); data already fully read before death (E2) may still back an event.

**R20 — nested runs and EBUSY.** `NEW_LISTENER` on a filter chain that already has one fails `EBUSY` (ARCHITECTURE
§3). The P0 launcher treats that as a failed start: a run started inside a run whose filter chain already has a
listener — tier 1 or tier 2 inside either, an `--observe` run included on either side — exits at startup with the
`EBUSY` wrapped as `launch.ErrChildSeccomp`, exit 125, before its agent runs, and nothing of it reaches the
ancestor's `Loop`. As built (measured 2026-09-24, `TestIntegrationANestedRunFailsAtStartAndLeavesTheOuterRunAlone`), the nested
launcher stops at an earlier step, still exit 125 before its agent runs: an enforced one at tier selection, whose
seccomp self-test's `NEW_LISTENER` fails `EBUSY` (`tier-unavailable`, naming the `EBUSY`); an `--observe` one inside an
`--observe` run at its `clone3`, which the outer filter refuses, or, as a root run's dropped agent, at placing its
scope. The outer run's supervisor goes on deciding the outer agent's syscalls to its own exit. **Condition (unbuilt design, §11):** routing a nested run's notifications to the ancestor's
`Loop`, its child stage getting no fd of its own, needs this `Loop` to learn the nested run's narrower composed
table (SEMANTICS §3), which nothing gives it; deciding them under the ancestor's broader `Policy` would widen the
nested contract, so until a nested run's composed policy can reach the ancestor's loop keyed by its cgroup, the
fail-closed start above is the rule. Dispatch/`Policy` lookup stays per-notification, never assumed to be one fixed
known pid — `notif.pid` is read fresh every time, not cached at construction — because one run's own threads and
processes arrive with different pids and cwds (R28).

**R21 — worker pool / starvation.** `Options.Workers` (default 4) goroutines each run a synchronous
`NOTIF_RECV → dispatch → respond` loop; at most `Workers` notifications are in flight, and the `(Workers+1)`th
notifying thread blocks *inside its own trapped syscall* until one frees up — deliberate backpressure onto the
agent, never onto the ledger (R23), never a `Loop` failure.

That bound holds only while every handler is microseconds long, and R9's connect-on-duplicate is not: it
inherits the target's blocking mode, so an allowed connect to a declared host whose route has started
dropping SYNs holds its worker for the kernel's whole retry schedule (~127 s at `tcp_syn_retries=6`). Four
of those park the default pool, and since only a worker inside `receive()` ever calls `NOTIF_RECV`, nothing
is received at all after that: every `openat`, `execve`, `mkdir`, `unlink` and `rename` of every thread of
the run stays trapped until one frees up. That is not the backpressure R21 intends and E17 measures; it is
the run stopping. **A worker about to wait on a relayed syscall therefore hands its place in the pool to a
standby worker and retires when its handler returns**, so *receive* capacity stays at `Workers` however many
relays are outstanding, while *decision* concurrency — what R21's backpressure is actually about — is
unchanged for every handler that does not relay. The standby workers are bounded instead, by
`maxStandby` (64, an unsourced P0 default): each costs one goroutine, and the parked relay it stands in for
holds one duplicate descriptor open; past that ceiling the pool degrades to exactly what it did before,
counted in `metrics.starved` and logged.

`maxStandby` bounds only the relays a handler is still parked on. A relay whose handler has already returned
— the target abandoned the syscall (E35), or the run was cancelled — keeps its goroutine and its duplicate
until the kernel returns, and E35's restart turns every abandonment into a fresh notification and a fresh
relay: an agent signalled on a loop while connecting to an allowed host that drops SYNs grows both with the
signal rate, with `standby` and `starved` at zero throughout. **The relay goroutines themselves are therefore
counted and capped at `Workers + maxStandby`** — exactly what the pool can have parked, so while every relay
is waited on the cap is never reached. Past it an allowed connect or Fast-Open send is not started: it is
refused with R10's errno, `rule: relay-limit`, counted in `metrics.relayLimited` and logged, the fail-closed
answer §7 gives a duplicate that cannot be taken. The cap lifts as the kernel returns the outstanding
syscalls.

*Amended 2026-10-16 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) Stage B):* a held open waits on the open deputy as a relay waits on the kernel,
and takes the same care: each request to the deputy that has not answered within 20 ms backfills the pool and polls
the notification (heldWait), and one the task left is abandoned (its late reply drained and closed, an open with an
effect counted `orphaned`). The deputy's outstanding requests are capped at `Workers + maxStandby`; past it a held open
is refused `held-limit`, never continued.

*Amended 2026-10-24 (ADR 0069 D2-D4), held reads:* a run whose table holds its reads (`RuleTable.ReadsHeld`) has
every open notified (enforce-landlock R16's amendment) and every read-capable open (`O_RDONLY`, `O_RDWR`, a
directory, `O_CREAT` with read access; never `O_WRONLY` or `O_PATH`) completed by the open deputy as a
`gate.completion: held` open is (`heldOpen`, `heldDirect`), with no gate needed: copied name, pin, object class (ADR
0041 D4), floors, the deputy's open, identity, `ADDFD|SEND`. Its floor (`heldFloors`) adds the held-read floor
(`heldReadFloors`, `decide.HeldReadIndex`): refused `read-denied`, naming the entry, when the pinned object lies at or
beneath a `deny_read` that is the nearest entry deciding a read there, nested or not; when a deny_read name rule
covers its name (a declared glob, a built-in home path, the built-in `.env` names beneath the scan's roots outside
the dependency directories), whenever it was made; or when it lies in tego's own state outside the run's own runtime
directory (`Options.RuntimeDir`) and outside a write entry nearer than that state. An allowed held read writes no
line unless the record mode keeps reads or a read gate scores it (`heldQuiet`), and neither does an open that held reads leave
as it was (an `O_PATH` open) and this loop does not refuse (`quietRead`, as for `fs.ask_read`); every
refusal writes its line and reaches the reason file. The tier-2 questions about the inherited ruleset (`listenerRefuses`) ask the ruleset alone
(`decide.LandlockRuleset`), never the tier's held-read answer. A run that holds its reads and whose deputy did not
start never reaches this loop (exit 125, ADR 0069 D6).

*Amended 2026-10-25 (ADR 0041 D4, ADR 0069 D2):* a held open whose pin was reached by a name that, when this loop
reads the pin, names no inode or another one (`errNameRemoved`, `errLinkedElsewhere`: a rename over the file, as an
editor's save or the ledger's own reason file write makes) is pinned once more, as the task's own open made now
walks the name again, and checked and scored on the second pin; that is D4's one re-pin, shared with a create's leaf
that appeared, and the second answer stands. A second such pin is refused `gate.unreadable` where a gate scores the
open and `held-unsupported` (no gate fields, authority `rule`) where it is held only as a read: the held-read floor
needs the object's name, and no gate decided it.

**R22 — per-notification budget.** 200 µs (P0-DESIGN §2.7) is a **soft** ceiling: exceeding it never aborts the
handler, only increments a slow-notification counter and, at `log.level: debug`, logs `recvAt`→now with `nr`. It is
distinct from the **typical measured** fast-path figure (<10 µs, P0-DESIGN §9) — see §11, parent report. The tests that
assert the round trip (`TestIntegrationFastPath`, `TestIntegrationFastPathOps`) hold the best of three runs to this
ceiling, or on a loaded box to 12 times a pipe ping-pong measured in the same run, in budget mode
(`make budgets`, uninstrumented). In the unit/race gate they use `testutil.CeilingFactor` times the 200 µs limit,
as the other cross-process timing tests do: a pipe ping-pong measures neither race instrumentation nor the
handler's CPU work. The production threshold is unchanged (ADR 0029, 2026-11-04 amendment).

*Amended 2026-10-06 (ADR 0048 (3)):* a guarded exec of more than 128 arguments whose decision needs its whole vector can exceed the 200 µs soft ceiling while it holds a worker; such a hold counts as an anomaly like any other, and `run_end.supervisor.exec_rules` counts the command rules' refusals.

*Amended 2026-10-16 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) §Performance, Stage B):* a held open (`gate.completion: held`) costs one or two exchanges with the open deputy on top of the copied path. `BenchmarkHeldOpen` measured, on a shared 16-CPU 6.17 host never idle: held p50 60–195 µs against the gated copy+walk+`CONTINUE` path's 29–85 µs, 2.01× at the median of nine runs (budget 2×: TARGET-MISS, which is why held completion is an opt-in); p99 85–379 µs, under 200 µs in seven runs of nine; 30,000 held opens across four workers 0.93–3.7 s (the idle-box budget of 1 s not measurable here); no thread made and no task /proc read per open; 22–27 allocations per open. In the 6.17 KVM guest with no CPU time stolen by its host, the root tiers' path (`BenchmarkHeldOpenRootTier`: the open after this loop's checks) held p50 117 µs against 28 µs, 4.14×, p99 157 µs, 30,000 in 1.83 s; tier landlock's 85 µs against 30 µs, 2.83×, p99 123 µs, 30,000 in 1.25 s (ADR 0041's Step 7 note).

*Amended 2026-10-17:* a notification's hold, in `run_end.supervisor.held_ms` and against this
ceiling, leaves out the time its lines waited for the previous notification of the same thread (R23a, `notif.waited`):
that time is the previous notification's emit, already in that one's hold. Counted twice, a single-thread UDP flood
under load (`TestIntegrationUDPFlood`) averaged two to three times the base's hold and missed the ceiling for order
keeping alone (`TestTheOrderWaitIsNotTheNotificationsHold`). `Options.Late` still gets the notification's finish.

**R23 — backpressure to the ledger.** Order is always **decide → respond (NOTIF_SEND) → emit**. A `Sink` that is
full waits for room up to its lane's bound (250 ms), then drops and counts (P0-DESIGN §2.4); either way it never
delays or changes the response already sent, and the backpressure falls on the worker's next notifications.

*Amended 2026-11-11, what a reader may rely on:* a refused call's line can reach `events.jsonl` shortly after the
agent has seen the refusal, at every tier. At tier landlock the supervisor answers the call, then the pipeline
writes the line (a write outside every write entry is answered `CONTINUE` and refused by Landlock in the kernel, and
its line follows that). At the root tiers the kernel refuses inside the call and the recorder reads the ring after
it; tier 2's fanotify listener and the supervisor's own refusals there (command rules among them) answer first and
write the line after, as at tier landlock (the root tiers read from the code, not run in a guest). In the runs read
the gap was well under a millisecond (0.33 ms for a refused `git push` on CI), and it grows with the box's load: in
one private gate run at load 15 to 27 three lines were written 17 ms after their notifications were received (read
from that run's ledger dump, not reproduced). The reason file trails the line by its window plus the timer's and
the box's delay (record-ledger.md §3), and a harness's hook tells only what the file lists when the hook reads it.
So a refusal is told by the first hook that runs once the reason file lists it, which can be a later hook than the
refused call's own, and the next model request: with 150 ms injected before each refused line was written, the
refused call's own PostToolUseFailure and PostToolBatch hooks both ran before its line landed, and the next turn's
PostToolUse told it. It is not dropped by a later hook: the hook's cursor is the highest seq it has shown, a line
that lands late has a higher seq, and the next hook tells it (or counts it as not listed when more than 32
refusals came since; REASON-CHANNEL §3). It is not told at all when no hook that tells runs after the file lists
it: a refusal that lands after the session's last such hook (a Stop hook that already kept the agent going once
stays silent) is not told by the hook, though the agent saw its errno. Either way the record holds its line, or a gap line that counts
it when the line was dropped (a lane full past its bound, P0-DESIGN §2.4; a ring overflow at the root tiers). A
reader that acts on a refusal (a test, a dashboard, a harness reading the reason file) waits for the line, with a
bound, and never takes its absence right after the refusal to mean the call was allowed. Rejected (2026-11-11):
holding each refusal's answer until its line and the reason file are written. Under review it left the agent's
thread unanswered when a handler returned without answering, a refusal flood cut the same run's allowed calls to
between a sixth and a half of their rate, and on kernels without `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (5.14 to
5.18, RHEL 9) the longer hold let signals turn many more refused calls into `EINTR`. In the runs reviewed no refusal
was lost under this order; a late one was told one model request later. GAPS C64.

**R23a — one thread's lines in the order of its syscalls** (*added 2026-10-16*). A line's
`mono_ns` is the `CLOCK_MONOTONIC` reading of its notification's receipt (`notif.recvMono`, taken under `recvMu`,
derived from the `time.Now` the receipt already reads and an anchor `New` takes, so no clock is read beyond it), not
the moment the line reached the pipeline. And a notification's lines wait, after its own answer, for the previous
notification of the same thread to finish writing its own, when that one was answered and still writing at receipt
(`admit`, `awaitPrev`, `order.go`). Before, the pool answered a thread's exec on one worker, the answer released the
thread, and its next exec (the next directory of a `PATH` search) was received, answered and emitted by another
worker before the first worker's emit reached the sink: one `bash` search was recorded with `/usr/sbin/bash` after the
`/usr/bin/bash` that ran, 105 µs later by `mono_ns`, and `tego learn` took the miss for the program. The answer path
is unchanged (decide → respond → emit, R23); the wait never delays the agent, and costs nothing when the previous
notification finished before this one was received, which is the common case on an idle box (no allocation:
`BenchmarkNotificationRoundTrip` includes `admit`, allocs/op equal before and after); under load a sequential
thread's next syscall regularly overlaps the previous emit. A linked wait yields up to 64 times, then parks on one of
the order book's waiters (a one-slot channel the previous notification's `retire` sends on, and the timer that bounds
the wait), set under the book's lock and given back to it after, so a park allocates only while more parks run at
once than ever before (about one per worker), and is left out of the waiter's hold (R22); it was a 20 µs sleep poll,
which a loaded box stretched, counted in the hold (*amended 2026-10-17*;
`TestTheOrderWaitEndsWhenThePreviousFinishes`). The park made a channel and a timer each time, four allocations, and
under load `BenchmarkSeccompNotifyRoundTrip` went from 14 to 15 allocs/op in some rounds and 6 % more B/op; with the
reused waiters it is 14 in every round again, and B/op 4 % below the per-park version with four busy loops on the
benchmark's own four CPUs (*amended 2026-10-17*; `TestAParkedOrderWaitAllocatesNothing`,
`TestATimedOutOrderWaitLeavesItsWaiterClean`). A previous notification that was *not* answered at
receipt is never waited for: its thread could make another syscall only because a signal withdrew the first (E35), and
that one may be parked on a relay or a person's answer. The wait is bounded at 1 s (above the lane's 250 ms for each
of the two lines one notification can write); past it the line is written anyway, out of order, the loop's
`order.lost` counter takes it into `run_end.supervisor.order_lost` (`Metrics.OrderLost`, R24), and the first in a run
is a `Warn` line in the own log (*amended 2026-10-16*: the counter was read by nothing and the log line
was `Debug`, below the default level). An answer that releases the thread without `respond`'s `Send`, the
`ADDFD+SEND` ioctl that completes an approved held open (`CompleteAskOpen`) or delivers an alternate (`DeliverFD`),
sets the notification's `sent` flag before the ioctl as `respond` does, so the thread's next notification is linked
to it too (*amended 2026-10-16*: neither set it, and the open's line could follow the next one's). So
does the open deputy's delivery of a held open under `gate.completion: held` (`DeliverHeld`, ADR 0041 Stage B), the
same ioctl (*amended 2026-10-19*, when R23a met ADR 0041 Stage B: the held delivery set no
flag; `TestAHeldOpenDeliveredByADDFDOrdersTheNextNotification`).
Rejected: emitting before the answer (breaks R23 and I5: a full lane would
hold the agent's syscall); pinning a thread's notifications to one worker (the receive is one shared `NOTIF_RECV`,
which cannot select by thread); a reorder buffer in the pipeline keyed on `mono_ns` (it would delay every line of
every source by the buffer's window). Order between threads, and between this loop's lines and the kernel
recorder's or forwarder's, is still the pipeline's arrival order; `seq` stays the record's only ordering key
(record-ledger.md R7). Because `mono_ns` is the receipt, a line of a syscall relayed for long says when it began,
not when it ended; the budget watcher's stall check, which reads `mono_ns` (limits-check-doctor-cli.md R4), learns of
the completion from `Options.Late`, which `finish` calls for every notification held past the soft ceiling with
`recvMono` plus the hold it already measured (*amended 2026-10-16*: a 50 s relay then 10 s idle
tripped `stall_after: 60s`; `TestASlowNotificationIsActivityAtItsFinish`).

**R24 — metrics for run_end.** `metrics.notifications` increments once per notification received (including R19
abandons and R25 recovered panics). `metrics.heldMS` accumulates `time.Since(n.recvAt)` per notification in ms,
monotonic-clock-derived (E14), summed not averaged. `Loop.Metrics()` is read once, after `Run` returns, into
`run_end.supervisor{notifications, held_ms, anomalies, orphaned, starved, order_lost}`: `anomalies` counts R22's holds
past the soft ceiling, `orphaned` E35's performed-then-abandoned syscalls, `starved` the relays R21's `maxStandby` could
not backfill, `order_lost` the lines R23a wrote without the previous line of their thread (*added 2026-10-16*, record
`record_minor` 11). The last four are optional in the record (`record-ledger.md` §2.2); `metrics.relayLimited` is not copied,
because each refusal it counts is already its own `net verdict=refused rule=relay-limit` line (§7). Before
2026-09-22 `orphaned` and `starved` were kept by the loop and read by nothing: an orphaned call left at most its own
`result_unknown` line and no total — and under `record: off`, where no allowed `net` line is written, nothing at all —
and a starved pool reached only tego's own log (`~/.tego/tego.log` for a CLI run), which is not the run's record.
*Amended 2026-10-16:* `metrics.execMissing` counts R16b (0)'s misses, the execs whose pathname named nothing, and is
copied as the optional `run_end.supervisor.exec_missing` (`record_minor` 8): those execs write no line, so this total
is their only trace (`TestExecMissWritesNoLine`).

**R25 — panic containment.** Every dispatch call (`handlerFunc`) runs inside a per-notification `recover()` in the worker loop, not the handler itself. A recovered panic: (a) logs `run=<id> nr=<n> id=<notif id> panic=<msg> stack=<stack>` to the own log only (§9), never the ledger — the stack is the goroutine's that panicked, so a relay goroutine's panic, re-raised on the worker (§7), carries the relay's frames, not the worker's (`TestHandlerPanicLogsItsStack`, `TestRelayPanicLogsTheRelayStack`); (b) if `NOTIF_ID_VALID(id)` still succeeds, responds fail-closed (R5) — `-EACCES`/R10's errno, every kind alike, outside an observe run (R30, where it is `CONTINUE`); (c) if `id` is no longer valid, behaves like R19 (abandon); (d) the worker loops back to `NOTIF_RECV` — never stops, never crashes `Run`, never leaves a sibling notification unanswered (I12, E34); (e) the recovery path's own answer and its `gap what=record why=handler-panic` line each run under a `recover()` of their own, since the line re-runs the emit path every handler shares and a panic whose cause is on it would otherwise panic again inside the deferred recover and end the process: a second panic is logged and swallowed, the answer having gone first (`TestPanicInTheRecoveryPathIsContained`); so does the fail-closed answer the notification's final accounting gives one still unanswered (I11), which runs after the recover has returned and retries that same path (`TestPanicInFinishIsContained`). Fills a gap the normative documents do not address; a P0 safety decision, not a sourced rule.

**R26 — unsupported `GOARCH`.** `New()`'s dispatch table is built per-`GOARCH` from R1's compile-time tables (amd64, arm64 only). The package is restricted to those two architectures by Go build tag (`//go:build amd64 || arm64`), so any other `GOARCH` fails to compile rather than panicking or silently building an empty, inert dispatch table — cheaper to catch in CI (`go vet`/`depguard`, I10). Not sourced to a normative document; a P0 engineering decision filling a gap the draft left unstated.

**R27 — `Policy` merge ownership for R8a.** `Policy` is compiled once, in `New`, into an immutable table that nothing swaps (I9), so the R8a "keep stale `Nets` on a failed re-resolution" merge cannot happen inside `Loop`. It happens in `dns.Set`, which `Policy.Resolver` is at run time: the set re-resolves each `NetRule.Host` when its TTL passes, substitutes only a successful answer, and `Match` reads the current addresses. The `models[]` guard's set is refreshed the same way by `Run`. `Loop` never partially updates or merges `Policy` itself.


**R28 — `PATH`-search candidates.** *Amended 2026-10-16:* a candidate whose directory holds no such name, the case
below calls common, is now a miss (R16b (0)): answered with its `ENOENT` and written as no line at all, in every run,
so this rule's `observed` line with `path_search: true` is left for a candidate that holds a file nothing grants (and
for a walk that failed otherwise). The candidate set and everything below still hold for those. `execvp` is not one syscall: glibc walks the run's `PATH` and calls `execve`
once per directory until one does not return, so one `python3` the agent asked for arrives here as one notification
per directory tried. Recording each miss as `refused, reason: exec-not-allowed` (a first version recorded five refusals for one
successful `python3`) reads as an agent reaching for five forbidden binaries when it reached for one granted
one, and `drift`/`measure` count it that way. A candidate the run's own search *has* to try before it reaches the
grant is therefore recorded `verdict: observed`, `rule: <the entry being searched for>`, **no** `reason`, and the
additive payload key `path_search: true`. It is answered by this loop with its own lookup's errno — `ENOENT` for the
directory that holds no such name, which is what the search walks on, and the refusal errno when something no entry
grants is there (R16b; never `CONTINUE`d, so a file planted at a candidate after the decision is not what the kernel
loads) — and, under `record: off`, suppressed like an allowed one: it is neither a refusal nor
a decision about the agent — nothing ran at that path.

The candidate set is derived once per policy (in `compile`, beside R15's filesystem table) from the compiled table
alone — no filesystem read, no state carried across notifications: for every exec entry **one of whose declared
spellings is a bare basename** (`ExecRule.ByName`: entries resolving to one file compile to one rule, which keeps
only the first spelling as `Raw`) and whose resolved path is `PATH[i]/<basename>`, the set holds
`PATH[j]/<basename>` for every `j < i`. A candidate is matched on the pathname the task passed, and one with a
`..` component is not one (R16b (3)): a search spells `PATH[j]/<basename>` with none. Its size is at most |`PATH`| × |basename entries|, and it is built once, in `New`, like the rest of
the table (I9).

Everything outside that set stays `refused, exec-not-allowed`: a different basename in a `PATH` directory; the same
basename in a directory that is not on `PATH`; the same basename in a `PATH` directory that *follows* the grant (a
search stops at the first `execve` that does not return, so it never gets there, and an `execve` naming one is the
agent's own doing); the same basename when the entry was declared only by path or by directory (that entry is
executed by its path and never searched for); a basename the contract granted nowhere, so a search that is never going to
succeed keeps every refusal it earns; and an empty or relative `PATH` element, which means the current directory
this package has no cwd for at policy time (`/proc/<pid>/cwd` is a per-notification read, R6, and each thread may
differ) — it falls through to the refusal, the fail-closed direction. Same-basename-anywhere is deliberately **not**
the rule: it would let an agent probe any directory it likes for `python3` and have every probe read as normal.

Holding no state is the point, and is why this is not a collapse of the failed candidates into the successful exec.
A collapse would need the loop to know an `execve` succeeded, which it never learns — it answers an allowed exec
`CONTINUE` and never sees the result, so "succeeded" could only be inferred from a later notification that does not come — and
would have to hold the successful exec back or write the candidates retroactively, against R23's decide → respond →
emit order and the append-only chain (I3). With R28, two threads walking `PATH` at once, a search that never reaches
its grant, a search interleaved with an unrelated `execve`, and a target that dies mid-search (R19) each decide on
one path string and are each right.

**R29 — one spelling of `rule`.** Every `rule` an event of this package carries is
`agent.FSRule/NetRule/ExecRule.RuleName()` or one of the sentinels of §9 (`unmatched`, `args-unreadable`,
`path-truncated`, `path-unreliable`, `fd-raced`, `fd-exhausted`, `ancillary-data`, `datagram-size`, `zerocopy`, `datagram-corked`, `batch-send`, `net.unspec`, `net.resolver`, `relay-limit`,
`relay-source-routed`, `relay-credentials`, `exec-anon`, `keyring`; *amended 2026-10-05:* `relay-source-routed`, a
net gate's relay refused for a source-routed socket, R9 and ADR 0041 D6, joins the list; *amended 2026-10-06, [ADR
0048](../adr/0048-exec-command-rules.md) (8):* an exec command rule's refusal names `exec.deny[<entry>]`,
`exec.ask[<entry>]` or `exec.args[<tool>]`, and `interpreter-unresolved`, `image-unreadable`, `loader-unresolved`,
`loader-program-unmatched` and `command-unresolved` join the list; *amended 2026-10-16 (R11a):* `unix-foreign`, a
socket under a write entry no process of the run bound, and `unix-origin-unread`, one whose binder the kernel could
not report, join it; *amended 2026-10-16:* `unix-bind-unrecorded`, such a socket while a bind of the
run went unrecorded, and `unix-absent`, a datagram's name that names nothing, join it; *amended 2026-10-16:*
`codex-home-exec`, a deny-list run's exec of an image or loader program in the run's own `CODEX_HOME`,
agent-contract.md R10a, joins it; *amended 2026-10-19:* `datagram-corked`, a UDP datagram that
could join or leave a pending frame, R13, joins it; *amended 2026-10-20:* `fd-unreadable`, a
descriptor `pidfd_getfd` refused with `EPERM`, R5, joins it; *amended 2026-10-20:* it also
names a descriptor that cannot be taken below 6.9 from a thread whose descriptor table is not its leader's, or whose
kernel's `kcmp` cannot say, R9's thread pidfd note; *amended 2026-11-02 (GAPS C34):* `relay-source-routed` also names
a relay refused under a `net:` section for a source-routed socket, R9, and a datagram whose control messages carry a
source route, R13b). `RuleName` spells the entry the
contract's author declared — `fs.write[./out]`, `net[api.github.com:443]`, `exec[python3]` — which is what
spec/record/v1/README.md means by "the declared entry or `unmatched`", and what `tego drift` registers the declared
side from. A position in the compiled list (`fs.write[0]`, `exec.allow[3]`) is not an entry anyone declared: the two
sides then share no vocabulary, so every declared entry reads "never used", every recorded rule reads undeclared,
and `drift` reports drift for every run that has ever executed. `ExecRule.Source` is not a rule name either — a
binary that is both the agent's command and an `exec.allow` entry carries the comma-joined `command,exec.allow`,
which is provenance, not a declaration.

Two entries may share a name: a glob that expanded to several paths keeps the glob text on every match, and Load
admits a duplicated entry with a warning. That is the intended reading — a reader of a contract counts declared
entries, not positions — so `drift` collapses them into one bucket, and nothing here keys anything by rule name.

**R30 — observe mode (`Policy.Observe`).** An explicit `tego run --observe` installs tier 1's filter with no
Landlock ruleset (P0-DESIGN §2.6) and runs this loop record-only. The runtime sets `Policy.Observe` from the
observe handle's `Verdict()`, which is `observed`. Every notification is read, matched and answered as in an
enforcing run, with two differences:

- **Nothing is refused.** Every errno this loop *chooses* as a refusal is answered `CONTINUE` instead, whatever its `rule` —
  for example a decided refusal (unmatched destination, `batch-send`, `relay-limit`, `relay-credentials`,
  `path-truncated`) and every R5 fail-closed answer (`args-unreadable`, `fd-raced`, a handler that returned
  unanswered or panicked, I11/R25). The kernel then performs the syscall on the
  target's own arguments. An admitted connect or Fast-Open send is still relayed on the duplicate and answered with
  its real result, errno included (I3). The two are told apart by who produced the errno: `respErrno` marks a
  refusal, `respResult` a relayed result. `respond` is the one place the swap happens, so no handler needs to know
  the mode.
- **Every action is `observed`.** Each exec, fs, net or mcp event is stamped `verdict: observed` with **no**
  `reason` as it is emitted, and keeps its `rule`: the entry it matched or a §9 sentinel. The ledger therefore
  says what the contract would have done without the run having done it. That is what `drift` reads, and what
  learn mode (P1) will read. Gap events are left as they are.
- **No `refused` line.** A refusal with no action kind is written on a `refused` line, which the ledger posts to
  `last-refusal.json` and the agent's reason channel; in an observe run that would report a refusal that never
  happened, so none is written. R31 writes nothing; R32 and R34 record the continued syscall as `gap what=record`;
  R13's pending-frame refusals that name no destination (`refuseOp`: a `setsockopt(UDP_CORK)`, and a `sendfile` or
  `splice` whose output descriptor could not be duplicated or read) are recorded as `gap what=record
  why=<rule>-<syscall> binary=<exe>`, for example `why=datagram-corked-setsockopt` or `why=fd-unreadable-sendfile`,
  once per binary, syscall and rule, as R32's are (per process, naming no binary, for a non-dumpable target, whose
  binary cannot be read: R31; that is `fd-unreadable`'s usual cause): no net line can name them, since nothing says which protocol or
  destination they carried. A pending-frame refusal on a `net` line (a send with `MSG_MORE`, a copy into a UDP socket)
  is stamped `observed` like every action. `emit` drops any other `refused` line in an observe run, with a warning in
  the own log, so a handler that forgets to ask the mode cannot write one (`TestObserveContinuesEveryFailClosedAnswer`,
  `TestTheRunCannotCorkASocket`, `TestAnObserveRunRecordsAPendingFrameRefusalItContinued`; end to end
  `TestIntegrationObserveRecordsPendingFrames`).

`record: off` keeps what it keeps in an enforcing run: the lines that would have been refusals, now `observed`.
A continued would-be-refused connect is performed by the kernel from the target's memory, so an agent that
rewrites its sockaddr between the read and the kernel's own copy can make the recorded `dst` differ from the real
one. That is R11's TOCTOU, accepted here because nothing is being enforced. An enforcing run never continues a
connect, so it never has this gap.

R30 governs the answers this loop gives, not the whole run. The filter answers some syscalls itself before any
notification, and an observe run installs tier 1's filter unchanged apart from enforce-landlock R2's truncation
arms, so its errno arms still apply: `ENOSYS` to every syscall of a non-native-arch or x32 process, so a 32-bit
or x32 binary cannot run under `--observe` (enforce-landlock R9); `ENOSYS` to `io_uring_*`, `openat2` and `open_by_handle_at` (R10
there); `EPERM` to `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)` (R11 there); and `EPROTONOSUPPORT` to
`socket(IPPROTO_MPTCP)` (E30 there). They stay for two reasons. The first is record completeness: an open or a
connect reached through a syscall number this loop has no entry for would never be recorded. The second is parity
with tier 1: tiers 1 and 2 install this same filter, so an agent recorded here meets the syscall surface that an
enforcing run gives it. The truncation arms are the exception because they refuse an fs action outright, in
Landlock's place. Installing the filter also means the observe child calls `NEW_LISTENER`. An `--observe` run
nested inside a run whose filter chain already has a listener (tier 1, tier 2 or another `--observe` run)
therefore fails at startup with `EBUSY`, as every nested run does (R20: the launcher's `launch.ErrChildSeccomp`,
exit 125). Before R30, an observe run installed no filter, so it started in that position and recorded nothing.

**R31 — the mount family (`landlock-topology`).** A Landlock domain refuses `mount(2)`, `umount`, `move_mount`
and `pivot_root` (`security/landlock/fs.c`: `sb_mount`, `sb_umount`, `sb_pivotroot`, `move_mount`) whenever it
handles filesystem rights, which both P0 tiers always do (enforce-landlock I4), so rootless podman, buildah,
bubblewrap and `unshare -m` cannot run inside a run (SEMANTICS §10, GAPS A9). The filter notifies the four
syscalls (enforce-landlock R11) and this loop answers each with `-EPERM`, the errno the domain gives — it cannot
succeed, and `path_mount` calls `security_sb_mount` before any capability check — so the refusal is certain rather
than inferred from what Landlock would do. Each refusal records a `refused` line, `reason: landlock-topology`,
`rule: unmatched` (no contract entry admits a mount in these tiers), `op` the recorded name (`mount`, `umount` for `umount2`, `pivot_root`, `move_mount`) and `target` the path it
would change (mount's target, `umount2`'s and `pivot_root`'s first argument, `move_mount`'s destination through
its dirfd; read under `ID_VALID`, R2); and the first refusal by each binary (`/proc/<tid>/exe`, bracketed) records
`gap what=enforce why=landlock-topology binary=<exe>`, at most 64 binaries a run. A binary that cannot be read is
recorded per process instead (`gapOwner`), and so are R30's, R32's and R34's once-per-binary gap lines: the kernel
reads `/proc/<tid>/exe` only past `ptrace_may_access(PTRACE_MODE_READ_FSCREDS)`, so a target that made itself
non-dumpable (ssh-agent, gpg-agent; the check that answers its `pidfd_getfd` `EPERM`, R29's `fd-unreadable`) hides
it. Such a process's first line names no binary and carries its `pid`, and its threads and repeats share it; keyed
by the empty name, every such process shared the run's first line and the later ones went unrecorded. Nothing outside that check names the binary: `comm` and `cmdline` are the agent's to
write. A process id the kernel reuses within the run shares its predecessor's line; the 64-entry cap counts
processes and binaries together (`TestAGapWhoseBinaryCannotBeReadIsOncePerProcess`). The four are decision kinds: a
handler that cannot finish refuses (with `refusalErrno`) rather than continues. Under `Policy.Observe` there is no
domain: `respond` turns the errno into `CONTINUE` (R30) and no line is written, since nothing was refused.

**R32 — the kernel keyring.** `add_key`, `request_key` and `keyctl` are notified (enforce-landlock R11). The
kernel keyring is a non-namespaced, same-uid credential store no `fs`, `net` or `exec` rule can see and no P0 tier's
hooks reach (Landlock has no keyring right; the BPF-LSM hook set has no `security_key_*` hook), so a run that used
it unseen could exfiltrate credentials — Kerberos tickets on a RHEL/IPA host's `KEYRING:persistent` ccache among
them — with no ledger line. The contract's `keyring:` scalar decides them (SEMANTICS §1):

- absent or `false`: refused with `-EPERM`, recorded `refused reason=read-denied rule=keyring op=<syscall>`, as
  Docker's and firejail's default seccomp profiles refuse them. `read-denied` is the closed-set reason nearest to "a
  credential store the run is denied"; the `keyring` rule and the `op` carry the specifics (REASON-CHANNEL §1).
- `true` (`Contract.Keyring`, read off the contract as `execUnrestricted` is): `CONTINUE`d.

A continued keyring syscall — under `keyring: true`, or under `Policy.Observe`, which enforces nothing whatever the
contract says — is recorded as `gap what=record why=keyring-<syscall> binary=<exe>`, once per binary and syscall in
the run (the `/proc/<tid>/exe` read is bracketed, R2; the set is capped like R31's, and a binary that cannot be read
is recorded per process, R31), so a Kerberos library's stream
of `keyctl` calls leaves one line and neither an opted-in run nor a learn pass over an observe run goes silent.
Record v1 has no keyring action kind, and a gap is the existing kind for "this happened and the record cannot
describe it as an action"; it names the syscall and binary, never a key id or payload. The three are decision kinds:
a handler that cannot finish refuses, never continues into the store unobserved (under observe, `respond` turns that
into `CONTINUE`, R30).

**R34 — System V IPC.** The eleven System V IPC syscalls are notified
(enforce-landlock R11) and answered as R32 answers the keyring's, under the contract's `ipc:` scalar (SEMANTICS §1):
absent or `false`, refused with `-EPERM` and recorded `refused reason=read-denied rule=sysv-ipc op=<syscall>`;
`true` (`Contract.IPC`), or `Policy.Observe`, `CONTINUE`d with `gap what=record why=sysv-ipc-<syscall>
binary=<exe>` once per binary and syscall (per process for a binary that cannot be read, R31). The IPC namespace is the host's at tiers 1 and 2 and its ids are
guessable, so a segment made outside the run was attached read-write inside it with no line (reproduced on 6.8 and
6.17). `read-denied` is the reason here, as for the keyring: a store outside the run that the run is denied; the
`sysv-ipc` rule and the `op` carry the specifics. They are decision kinds (a handler that cannot finish refuses).
The two opt-ins are separate: `keyring: true` does not continue IPC. Test: `TestSysVIPCIsRefused`,
`TestSysVIPCUseIsVisibleWhenContinued`, and on the kernel `TestSysVIPCIsRefusedAtTierOne`.

**R33 — the signal scope below Landlock ABI 6** (enforce-landlock R7). Below
ABI 6 the filter notifies the kill family and `fcntl(F_SETOWN/F_SETOWN_EX)`, and this loop decides each as
`LANDLOCK_SCOPE_SIGNAL` decides it from ABI 6: continued when every process the call would reach is in the run's
cgroup or one beneath it (`Policy.Cgroup`, read from `/proc/<pid>/cgroup`), refused `-EPERM` otherwise and recorded
`refused reason=landlock-topology rule=signal-scope op=<syscall> target=<pid, thread or process group>`. Signal 0 is
decided the same way, as the scope decides it. `kill(-1)` is always refused; `kill(0)` and a negative pid are decided
over every member of the process group, and the agent shares its launcher's group, so `kill(0)` is refused; its
line names the group `kill(0)` resolved to. A signal
to the caller's own process (`tgkill` to itself, `raise`, the Go runtime's preemption) is continued with no `/proc`
read. A `tkill`, `tgkill` or `rt_*sigqueueinfo` naming a pid of 0 or below signals nothing and is continued unread
for the kernel to answer (`EINVAL`, or `ESRCH`). `F_SETOWN_EX`'s owner is read from the caller's memory, best effort like every memory read here (§1); a target
that no longer exists is continued and the kernel answers `ESRCH`. The kernel re-resolves a continued pid, so a
target that exits and whose pid a process outside the run takes in the interval gets the signal: best effort, as
every continued decision is; the kernel scope from ABI 6 has no such window. A group's members are read from one
scan of every `/proc/<pid>/stat` on the host, shared by the group signals of the next 50 ms when it found the group
(a group it did not find is scanned again, since an empty group is continued, but only when the process whose pid
is the group's id is in that group now: `setpgid(p, p)` and `setsid` put a new group's leader in it, so a pgid whose
process is gone or in another group is answered empty from the snapshot with one `stat` read, and `kill(-N)` in a
loop on a group that does not exist costs no scan per call); a process outside the run that
joins the group inside that window, which only one of the launcher's own session can do, is not seen, nor is a
group made since the scan whose leader has already exited or left it: the same best-effort class. The scan skips only a process that exited during it; one whose `stat` it cannot read for any
other reason (`EMFILE`, `ENOMEM`, `EACCES`, a malformed line) may be an outside member, so the scan fails, is not
kept, and the signal is refused with a warning, as an unreadable single target is.
`ioctl(FIOSETOWN)` and `ioctl(SIOCSPGRP)` set the same owner record as `F_SETOWN` (`sock_ioctl` → `f_setown`), and
with `F_SETSIG` and `O_ASYNC` a byte written to the socket's peer would send the chosen signal to any process of the
uid, the launcher included (reproduced at ABI 5). The arm notifies those two requests too, matched on the
request's low 32 bits as the kernel reads it (bits above 31 are ignored by filter and handler alike), and this loop reads
their int owner from memory (a pid, or a process group when negative) and decides it as `F_SETOWN`; that read is
best effort like `F_SETOWN_EX`'s (§1: another thread can rewrite the int after it), a window the kernel scope from
ABI 6 does not have. The seven — the six calls above and `ioctl` — are decision kinds: a handler that cannot finish
answers `EACCES` (R25), not the `EPERM` of a decided refusal. Stated limit: `tkill`/`tgkill` carrying `SIGURG`, the Go runtime's preemption signal, is
allowed by the filter without a target check, so a process of the run can send `SIGURG` to any thread of the uid
below ABI 6. Its default action is to be ignored and a Go launcher treats it as preemption; a program of the user
that handles `SIGURG` itself can be poked.

**R35 — the process scope, at every ABI** (enforce-landlock R7). No Landlock ABI governs a change to another
process's resource limits or scheduling: `task_prlimit`, `task_setnice`, `task_setscheduler` and `task_setioprio` are
LSM hooks Landlock does not implement, and the kernel's own check is only that caller and target share a uid, which
at tier 1 the agent and its launcher do. Inside an ABI-6 signal scope, `prlimit64(launcher, RLIMIT_CPU, {1, 1})` had
the kernel `SIGKILL` the launcher, supervisor and ledger writer with it, and the run ended with no `run_end`
(reproduced on 6.17); `RLIMIT_FSIZE` 0 or a low `RLIMIT_NOFILE` crippled it instead, and `setpriority` or
`sched_setaffinity` starved it while every notified syscall of the run waited on it. The same calls reached every
other process of the user. So every enforcing run's filter notifies `prlimit64` with a non-zero pid and a new limit,
`sched_setparam`/`sched_setscheduler`/`sched_setaffinity`/`sched_setattr` with a non-zero pid, and `setpriority` and
`ioprio_set` unless they name the caller's own process (`PRIO_PROCESS`/`IOPRIO_WHO_PROCESS` with who 0); a call on
the caller itself and a `prlimit64` that only reads are allowed by the filter. This loop decides each as R33 decides
a signal: continued when every process it reaches is in the run's cgroup or one beneath it, or is a thread of the
caller's own process (no cgroup read), refused `-EPERM` otherwise and recorded `refused reason=landlock-topology
rule=process-scope op=<syscall> target=<pid, process group or uid>`. A process group (`PRIO_PGRP`, `IOPRIO_WHO_PGRP`, who 0
the caller's own, which it shares with the launcher) is decided over every member; a uid (`PRIO_USER`,
`IOPRIO_WHO_USER`) is always refused, its line naming the uid ("the caller's uid" for who 0). A target that no longer exists is continued and the kernel answers `ESRCH`; a
negative pid or an unknown `which` is continued for the kernel to refuse. A loop that does not know the run's cgroup
refuses. The kernel re-resolves a continued pid, the same best-effort window as R33's. The seven are decision kinds.
Test: `TestProcessScope`, `TestProcessScopeFailsClosedWithNoCgroup`, and on the kernel
`TestTheAgentCannotChangeAProcessOutsideTheRun`.

**R36 — a watch of a `deny_read` target** (*added 2026-11-02*, GAPS A10; enforce-landlock R11e). A watch opens
nothing: `inotify_add_watch(2)`, `fanotify_mark(2)` and dnotify's `fcntl(fd, F_NOTIFY, mask)` ask only DAC's
`MAY_READ` of the object (dnotify, on a descriptor already open, not even that) and `security_path_notify`, which
neither Landlock nor the decision plane implements, so a watch on a `deny_read` directory was made at every tier and
reported which of its files were opened, read, written and closed, while every read of them was refused. Every
enforcing run's filter notifies the three (enforce-landlock R11e; *amended 2026-11-02*: the first version installed
the arm only where the table's fs rows withheld a read beneath a target, which left out a table whose only withholding
was a name entry or rule or tego's own state, and every run a live block or fence entry later narrows), and this loop
decides each (`watch.go`):

- `inotify_add_watch(fd, pathname, mask)`: on the object `pathname` names from the task's cwd, its final symlink
  followed unless `mask` carries `IN_DONT_FOLLOW`.
- `fanotify_mark(fd, flags, mask, dirfd, pathname)`, by `flags`, a register read as the kernel reads it: an inode mark
  added is decided on the object `dirfd` and `pathname` name, `dirfd`'s own file (its `/proc` link) when `pathname` is
  NULL, a final symlink followed unless `FAN_MARK_DONT_FOLLOW`; a mount, filesystem or mount-namespace mark added
  (privileged: `setuid: true` at a root tier) reports every file it covers, the targets that share its mount included,
  so it is refused wherever it is placed, with `EPERM`, the kernel's own answer to a caller without `CAP_SYS_ADMIN`
  (every other agent), rule `deny-read-watch`; a removal and a flush add no mark and are continued, and so is a call
  the kernel fails for its own reason (no single command, `EINVAL`; a negative `dirfd` with no pathname, `EBADF`).
- `fcntl(fd, F_NOTIFY, mask)` (*added 2026-11-02*: the first version decided only the two calls above, and a
  descriptor of a `deny_read` directory, which a tier-1 ruleset lets the agent open to list on the `READ_DIR` it
  inherits, placed a dnotify watch that reported every access, change, creation and rename inside the target): on
  `fd`'s own file, its `/proc` link, as a fanotify mark of a descriptor is, under `op` `fcntl`. The filter tests the
  command alone, so no other `fcntl` reaches this loop for it (enforce-landlock R11e), and `handleFcntl` hands the
  signal arm's `F_SETOWN` pair on to R33 as before. The kernel reads `fd` and `mask` as unsigned ints: a mask with no
  event bit (0, or `DN_MULTISHOT` alone) removes the descriptor's watches and adds none, and a descriptor number past
  `INT_MAX` names none (`EBADF`, never read as the cwd); both are continued. A descriptor that is no directory is
  decided all the same (the kernel would answer `ENOTDIR`): whether it is one is a stat this loop cannot trust.

A watch of an object is refused, with R10's errno (the `EACCES` a read of the object meets), where a read-open of it
is refused (`watchDenied`; *amended 2026-11-02* after review, which found the first version asked only the read
verdict, and that only for `read-denied`, and the held-read floor's (a) and (c)):

- the read verdict (`fsVerdict`): the nearest entry deciding a read is a `deny_read` the run's tier enforces, an absent
  built-in row, or at tier cgroup a name entry, whose climb that cannot decide within `agent.MaxWalk` refuses
  `path-unresolved` under `unmatched`, as the listener refuses the read, and the line carries that reason;
- at tier bpflsm a name entry too (ADR 0043 D7), whose file's read the plane's name check refuses though the read
  verdict leaves name entries to tier cgroup: asked where the declared links lead, as the verdict asks it there;
- in a run that holds its reads, the floor `heldReadFloors` applies: a target nested in a write entry and a
  `deny_read` name rule (ADR 0069 D3 (a) and (c), `decide.HeldReadIndex`), and tego's own state, the table's and the
  launcher's runtime parent but the run's own runtime directory (D3 (d), `heldOwnState`), under
  `fs.deny_read[<that path>]`;
- a live read or path block, or an Adjustable run's read fence entry not lifted (the live Set, under
  `live.block[...]` or `live.fence[...]`), which `liveFS` and `heldReadFloors` refuse a read under. It is asked of
  every watch this loop is notified of, also in a run whose reads it does not see (where a read block cannot be
  placed and a path block refuses only changes, OPERATIONS "Live blocks"): it only tightens.

A directory is told by a stat of its final name, since a name entry or name rule covers files alone. A watch beneath an
`fs.ask_read` entry, whose read would be held for a person, is refused under that entry: a watch has no answer to wait
for. A read only the `deny_read` snapshot refuses (R15e) is not one: nothing there is a target. A read gate's score is
not asked: a gate scores actions, and a watch is none it scores. The object is matched as R15c matches an end, by its
line's name and then where the task's own lookup lands (`matchEnds`), so a symlink, a `..` or a `/proc/self/fd` link
into a target is refused under the target's rule; and it fails closed as R15c does: a pathname that could not be read
whole (`args-unreadable`, `path-truncated`), a descriptor whose link this loop may not read (`fd-unreadable`: a
non-dumpable task at tier 1) and a walk that failed other than as the task's lookup fails (`path-unreliable`) are
refused under that marker. Each refusal is a `refused` line, `op` the syscall, `target` the watched name,
`reason: read-denied` (`path-unresolved` where a name entry's climb could not decide), `rule` the target's entry, the
block or fence entry, or the marker, written under `record: off` too; a continued watch has no line, since record v1 has
no watch kind. Under `Policy.Observe` the call is continued and no line written (R30); the observe filter carries no
such arm. Best effort, as R15c is: the kernel reads the pathname and resolves it again after `CONTINUE`, so a sibling
thread that rewrites it, or a process that repoints a link or swaps the descriptor, in between places the watch where
this loop did not decide. A watch of the directory that holds a target is not refused: it reports a target file's own
activity (an open, a change) and a target directory's own entry, as a listing of that directory shows their names
(SEMANTICS §1). Each watch costs one notification in every enforcing run, whatever its contract (the first version's
predicate saved no `tego run` the cost: every table it compiles withholds tego's own state, agent-contract R6a, so the
arm was in every such run already), so a watcher that adds one per directory of a large tree pays one per directory:
about 25 µs a watch against 2 µs unnotified (3000 inotify watches of allowed directories through the harness's filter,
6.17, 2026-11-02), a quarter of a second for ten thousand. A dnotify watch costs the same, and no other `fcntl` is
notified for it. Test: `TestWatchBeneathADenyReadTargetIsRefused`, `TestDnotifyOfADenyReadTargetIsRefused`,
`TestWatchFollowsTheKernelsLookup`, `TestWatchDecidesAsTheRunWithholdsReads`, `TestWatchFollowsEveryReadRefusal`,
`TestWatchOfAnAskReadEntryIsRefused`, `TestWatchOfAnUnreadableDescriptorIsRefused`,
`TestWatchInAnObserveRunIsContinued`, on the kernel `TestIntegrationWatchBeneathADenyReadTarget`, and through a
tier-landlock run's ledger `TestIntegrationAWatchOfADenyReadTargetIsRefused`.

**Changes.**
- 2026-11-11, R23: says what a reader may rely on. A refused call's line can land after the agent saw the refusal,
  at every tier, so a hook tells it once the reason file lists it, possibly at the next model request, and a reader
  waits for the line (GAPS C64). The order is unchanged; holding each refusal's answer for its line was rejected.
- 2026-11-02, R1, R36 (GAPS A10): the watch calls are notified in every enforcing run. The arm was installed only
  where the table's fs rows withheld a read beneath a `deny_read` target, so a run whose only withholding was a name
  entry, a name rule, tego's own state or a live block or fence entry (which arrives after the filter is built) kept
  its watches undecided; and the cost note said the arm was in runs with a `deny_read` entry, when agent-contract
  R6a's own rows put it in every `tego run` already.
- 2026-11-02, R36 (GAPS A10): a watch was refused only where the read verdict refused its object's read for
  `read-denied`, or a held read's floor (a) or (c) did, though R36 said a watch follows the run's reads. A file a name
  entry covers at tier bpflsm (the plane refuses its read by name), a name entry's climb that cannot decide (its read
  is refused `path-unresolved`), tego's own state in a run that holds its reads (floor (d)) and a live read or path
  block or read fence entry kept their watches. `watchDenied` asks each, and the line carries the read's reason.
- 2026-11-02, R1, R36 (GAPS A10): dnotify, the third watch API, was still open: `fcntl(fd, F_NOTIFY, mask)` on a
  descriptor of a `deny_read` directory, opened to list, reported every access, change, creation and rename inside it
  (reproduced at tier landlock: an outside read of a file in the target signalled the agent, and no line was written).
  `fcntl`'s `F_NOTIFY` is dispatched with the other watch calls and decided on the descriptor's own file, `op`
  `fcntl`; a removal and a negative descriptor are continued.
- 2026-11-02, R1, R36 (GAPS A10): a watch of a `deny_read` target was made at every tier, since no Landlock or plane
  hook sees one, and reported which of its files were opened and changed. `inotify_add_watch` and `fanotify_mark` are
  dispatched in a run that withholds a read beneath a target, and a watch whose object a read of would be refused is
  refused `EACCES` with a `refused` line under the target's rule; a whole-mount fanotify mark is refused there too.
- 2026-11-02, R9, R13b, R29 (GAPS C34): under a `net:` section with no gate the relayed connect and Fast-Open send
  followed the socket's source route, and an admitted datagram, connected or not, the route its own control messages
  carried, to a first hop no entry admits. The options read before a relay is made under every `net:` section, and a
  `sendmsg` or `sendmmsg` whose control messages route its datagram is refused `relay-source-routed`, best effort
  against a sibling's rewrite of the buffer.
- 2026-11-01, R5, R25 (b), failure table: a fault of this loop's own is refused for every kind (`failClosed`), and
  `entry.decision` and `fsGuarded` are gone; a read-open continued a held read past a panic, and any fs row continued
  what a live block refuses (`TestEveryHandlerFaultRefuses`, `TestHandlerFailureKeepsWhatOnlyTheHandlerKnew`).
- 2026-11-01, R16: the command rules' staged argv read decides a vector of exactly 8192 pointers,
  as the record's read does; a last batch of pointers that ended on the bound left the NULL after it unread, so a
  guarded exec of exactly 8192 arguments was refused `args-unreadable` (ADR 0048 R7 refuses only past the bound)
  (`TestExecCommandReadsAVectorOfExactlyTheBound`).
- 2026-10-27, R16b (ADR 0048 C8): at tier landlock an exec's absolute pathname
  and each `#!` interpreter's are looked up by an RCU-only `openat2` and then one with `RESOLVE_NO_XDEV` where that is
  provably the component walk's lookup; the walk answers everything else; a run with command rules opens the task's
  root once per exec (*The walk*, amended). A `#!` interpreter's walk of `/bin/sh` with its head: 24.3 us -> 14.1 us.
- 2026-10-25, R7a: a held open's kernel EACCES is explained by the opened
  object's identity too where a plane decides, so a plane's refusal of a hard-link alias is written refused under the
  rule its row answers with, not the floor's allow (GAPS C38).
- 2026-10-25, R15c: the reopening write entry's own name is the
  `fs.deny_write` entry's: a rename of it and a modification that makes it are refused; the held open's floor and the
  write gate ask the table's index.
- 2026-10-25, R15c (ADR 0071): a contract's `fs.deny_write` entries are refused with the built-in
  targets, named `fs.deny_write[<entry as declared>]`, a write entry strictly beneath one reopening its subtree.
- 2026-10-25, R15 (ADR 0077): a read open continued at tier 1 that the Landlock ruleset refuses
  under `deny_read` carries `mechanism: landlock`; `reason.reads: on` notifies every read open there, quietly for an
  allowed one; the runtime's `refused` mirror copies `mechanism` and `decision_plane`.
- 2026-10-25, R7b (ADR 0070 (3) amended): stream sends are relayed on the
  duplicate; an addressed send on a connected socket is neither decided nor recorded (`sendConnectedUnixOnly`), a
  seqpacket one continued; a socket of another domain is refused `host-sockets`, save a route query to the kernel,
  relayed as the task.
- 2026-10-25, R7b (ADR 0070 (5) amended): the root tiers keep R7b unchanged, a plane
  leaving connect and sendmsg notified; the race test and the conformance table are named.
- 2026-10-24, R7b (new, ADR 0070): the unix-only state of a contract with no `net:` section relays every
  connect and refuses a unix destination the run did not bind, rule `host-sockets`.
- 2026-10-24, R7b: an admitted addressed datagram of the unix-only state is relayed on the
  duplicate (a unix one as the task, `SendUnixAs`); one the relay cannot reproduce, an unaddressed `sendmsg` and a
  `sendmmsg` batch are continued, best effort, run_start cell `host_sockets/datagram`.
- 2026-10-25, R15 and R7a (ADR 0069 D2): at tier 2 and 3 an `O_PATH` open beneath a `deny_read` is
  recorded `allow` by that entry with the marker ` (O_PATH: reads nothing)`, as at tier 1, and its line is this
  loop's even while the kernel recorder reads: the open reaches no hook of the recorder (`fexit/security_file_open`),
  of the fanotify listener or of the decision plane, all of which run after `do_dentry_open`'s `O_PATH` return. It was
  recorded `refused` for an open the kernel let through where no recorder read, and was handed over to a recorder
  that never wrote it (or, at tier cgroup, left to a listener that never saw it) where one did: the earlier
  entry's "Tier 2's naming, which its kernel recorder or listener writes, is unchanged" was wrong for
  `O_PATH`. Such an open now leaves a tombstone, as a refusal does, so a later record of the thread inherits no
  naming from it, and `listenerRefuses` never answers one (`TestHeldReadsOPathAtARootTier`, cgroup and bpflsm,
  `record: full` and `summary`, with and without a recorder, failed before; `TestAdvisoryOPathOpenUnderADenyRead`'s
  root-tier rows).
- 2026-10-25, R21 (ADR 0069 D4): in a run that holds its reads, an open the loop neither holds nor
  refuses and no read gate scores (an `O_PATH` open, which held reads leave as it was) gets no line under `record:
  summary` or `off`, beneath a `deny_read` or not, as in an `fs.ask_read` run: `quietRead` covers held runs too. Each
  such open of a benign file or directory wrote `allow by fs.write[...]`, and one beneath a `deny_read` its `(O_PATH:
  reads nothing)` line, where a summary run without held reads was never told of them
  (`TestHeldReadsOPathLinesSayWhatHappened` now runs under `full`, `summary` and `off`; its summary rows failed
  before).
- 2026-10-25, R15 (ADR 0069 D2): at tier 1 an `O_PATH` open beneath a `deny_read`, enforced or nested
  in a write entry, is recorded `allow` by that entry with the marker ` (O_PATH: reads nothing)`: the kernel runs no
  `file_open` hook for one, so the Landlock ruleset refuses none and held reads hold none, and every read through its
  descriptor is another open. Its line said `refused` beneath an enforced entry, for an open the kernel let through
  (`record: full`, `fs.ask_read` and held-read runs, where such opens are notified), and ` (unenforced: parent
  writable)` beneath a nested one in a run whose capability line says `fs.deny_read.nested` holds
  (`TestHeldReadsOPathLinesSayWhatHappened`, `TestAdvisoryOPathOpenUnderADenyRead`; both failed before). Tier 2's
  naming, which its kernel recorder or listener writes, is unchanged.
- 2026-10-25, R7a and R21 (ADR 0041 D4, ADR 0069 D2; R21's amendment of that date): a pin whose name was removed
  or replaced after the deputy's walk is re-pinned once before it is refused. Held reads hold every read of a run,
  and a read that raced a rename over its file was refused `gate.unreadable`, with a gate's fields in a run with no
  gate: the run's read of its own reason file while the ledger rewrote it failed 3 times in 140. The second
  such pin is refused `gate.unreadable` under a gate that scores the open and `held-unsupported` otherwise
  (`TestHeldReadOfAFileReplacedAfterThePinIsRepinned`, `TestHeldReadWhoseNameKeepsBeingReplacedIsRefused`;
  `TestHeldPinWhoseNameIsRemovedIsUnreadable` now has a sibling that removes the target once, the second walk's
  `ENOENT`, and one that replaces it after every pin, refused). The 2026-10-16 entry's property stands: such a
  pin is never decided on the copied name.
- 2026-10-24, R7a, R15 and R22 (ADR 0069 D2-D4): held reads, the amendment under R21.
- 2026-10-27, R15f (ADR 0043 C11): the name entries' refusals at tier 2 apply in every build; the build
  switch `agent.NameEntriesEnforced` they waited on is gone.
- 2026-10-20, R17 (ADR 0029 (4)): REFER's no-gain rules are named as the code
  asks them, `decide.RenameGainedBy` with `decide.ReferRefuses` for a rename and `decide.LinkGainsBy` for a link;
  `decide.RenameGains`, `RenameGained` and `LinkGains`, wrappers over them that only decide's tests called, moved
  into decide's test files. No decision changed.
- 2026-10-19, R11 and R11c: the name decision compile --test's property test
  asks (`decideUnixName`) takes the connect's scope question (`unixScopeOf`, nil for a datagram and for compile), so a
  connect whose name reaches a `net.ask` `unix:` scope's place is still not admitted by the write entry around its
  spelling; the relay's decision on the socket reached (`unixAdmit`) is skipped at an approved scope's own place, as
  before; and a connect's line keeps `grantedUnixVerdict` (an approved abstract name's connect the grant no longer
  covered is `observed`) inside `unixConnectLine`'s verdict. The supervisor's `unix-ask-scope` is
  `agent.UnixAskScopeRule`, the name compile --test now answers with. No verdict or line changes.
- 2026-10-20, R30, R31, R32 and R34: a
  once-per-binary gap line whose binary cannot be read (a non-dumpable target's `/proc/<tid>/exe`, which the same
  ptrace check as its `pidfd_getfd` refuses) is written once per process, naming no binary and carrying its `pid`.
  Keyed by the empty name, an observe run wrote one `fd-unreadable-sendfile` line for its first non-dumpable process
  and none for any other, reproduced at tier 1 on 6.17 with two non-dumpable binaries. Rejected: naming the process
  by `comm` or `cmdline`, which the agent writes (`PR_SET_NAME`, its own argv), so a line would name a binary
  nothing read; the run's exec record, which says what was asked to run, not what the process runs now, and
  would need a per-process table kept across exec, fork and failure; documenting one line per run, which leaves a
  second process's calls unrecorded (`TestAGapWhoseBinaryCannotBeReadIsOncePerProcess`; the fake now refuses a
  non-dumpable target's `exe`, `cwd`, `root` and `fd/<n>` links as the kernel does).
- 2026-10-20, R9's thread pidfd note and R29: below 6.9 a secondary
  thread whose descriptor table is not its leader's, and a kernel whose `kcmp` cannot tell (`ENOSYS`), are recorded
  `fd-unreadable`, where they were `fd-raced`, which blamed a race for a lasting property of the thread
  (`TestConnectDecisions`, `TestTgidFallbackRefusesAThreadWithItsOwnFDTable`).
- 2026-10-20, R30: an observe run writes no `refused`
  line. Since the observe filter carries the pending-frame arms (enforce-landlock R11d), its
  supervisor continued a `setsockopt(UDP_CORK)` and a `sendfile` or `splice` whose descriptor it could not read, yet
  wrote a `refused` line for each, which reached `last-refusal.json` and the agent's reason channel, and which `drift`
  and learn counted as refusals. Each is now `gap what=record why=<rule>-<syscall>`, once per binary, syscall and rule,
  and `emit` drops any `refused` line in an observe run. Rejected: writing nothing, as R31 does, which would leave
  learn mode and `drift` a record that under-reports what the contract refuses (the reason R11d's observe arms were
  added); an `observed` net line, which would name a protocol and a destination nobody read.
- 2026-10-20, R5, R13 and R29: a descriptor `pidfd_getfd` refuses with
  `EPERM` (at tier 1 a target that made itself non-dumpable) is recorded `fd-unreadable`, a new sentinel, where it was
  `fd-raced`, which blamed a race that did not happen; and a `sendfile` or `splice` whose output descriptor could not
  be duplicated or read is still refused, fail-closed, but on a `refused` line, op `sendfile` or `splice`, target
  `fd <n>`, where it was a net line claiming a refused `tcp` operation for what may be a file copy. The failure table
  and enforce-landlock R11d now say that such a process's every `sendfile` and `splice` is refused in a run that
  decides datagrams (`TestASendfileOrSpliceIntoAFrameSocketIsRefused`, `TestConnectDecisions`,
  `TestUnresolvedWithNoNetSection`; end to end `TestIntegrationNonDumpableFileCopy`).
- 2026-10-20, R1, R13, R13d and R11c (ADR 0008's design note): a pending frame is decided from the socket where it forms, in one place per syscall
  family, in a run that decides datagrams: `MSG_MORE` on any `sendto`, `sendmsg` or `sendmmsg` on a UDP, UDP-Lite or
  raw IP socket, `setsockopt(UDP_CORK)`, and `sendfile` or `splice` into such a socket are refused `datagram-corked`
  (the filter notifies the unaddressed `sendto`, the cork, `sendfile` and `splice` for it); the per-path checks, which
  took a batch's protocol from its first address, are gone. At tiers 2 and 3 an approved datagram whose credit the
  kernel left untaken is recorded `observed`, not the person's allow; the one-shot credits are
  serialized by their granter by the map's own key, where the supervisor's key kept the IPv6 zone the map drops. Before,
  a UDP batch with `MSG_MORE` whose first address was a unix name left a frame that the next approved datagram joined
  under a line naming its own port, and two approved datagrams to one link-local address on two scopes collided.
- 2026-10-19, R13 and R11c: a UDP-Lite socket keeps UDP's
  pending frames and is refused `datagram-corked` as a UDP one is; an unaddressed UDP `sendmsg` or `sendmmsg` with
  `MSG_MORE` under a `net:` section is refused `datagram-corked`, guard or gate or none, where it was continued; an
  abstract-name grant is serialized per socket, not per socket and name, as `tego_unix_approvals` keys its row. Before,
  a relayed UDP-Lite datagram joined a frame bound for another port under a line naming its own, and two approved
  connects of one socket to two names refused one of them `ask-unavailable` or lost its credit to the other's revoke.
- 2026-10-19, R13, R13d and R29: a UDP datagram that could join or leave a
  pending frame is refused `datagram-corked`: `MSG_MORE` on a relayed datagram, on an addressed UDP datagram or
  `sendmmsg` batch under a `net:` section, and a relay on a socket whose `UDP_CORK` is set or unreadable. Before, an
  approved datagram relayed onto a socket holding a frame to an admitted port went there under a person's allow line
  naming the approved port. A frame a send this loop never sees leaves is the disclosed residual.
- 2026-10-19, R13d and R11c: the grants an approval makes at tiers 2 and 3
  (`GrantDatagram`, `GrantConnect`, `GrantUnix`) are serialized per socket cookie and destination or name: a second
  approved operation of one key waits, up to a second, for the first's credit to be withdrawn instead of being refused
  `ask-unavailable` or losing its credit to the first's revoke.
- 2026-10-19, R13d: a socket's datagram approval under a net gate is kept
  with the gate's verdict, score and rule, so a later datagram to that destination the gate scores otherwise is asked
  again; before, the approval admitted it unasked at whatever score the gate gave it.
- 2026-10-19, R13d added (ADR 0008's note of that date): an addressed UDP datagram or a UDP connect whose
  destination a `net.ask` `udp://` or bare `host:port` scope reaches is held for a person and, once approved, relayed
  from the copies read before the wait; an approval covers the socket's later datagrams to that destination; at tiers 2
  and 3 each relayed operation is granted once by `tego_connect_approvals` (UDP keys). Before, such scopes did not
  compile, and a UDP connect a scope reached was refused `ask-unavailable`.
- 2026-10-19, R11c (ADR 0023's ratchet): `Options.GrantUnix` takes the
  socket's cookie, not the duplicate's number. `askUnix` checks the duplicate is `AF_UNIX` (`SO_DOMAIN`) and reads its
  `SO_COOKIE` before granting, which the tier-2 handle's `GrantUnix` did from the number before; a socket that is not
  `AF_UNIX` is still refused `ask-unavailable` after the approval, with no grant and no connect
  (`TestAskUnixHoldsTheConnectAndRelaysTheApprovedSocket`). No verdict or line changes.
- 2026-10-19, R11c: `agent.ResolveUnixPlace`
  keeps a name it could not read as a plain name only when the read says what it is: `EINVAL` (no symlink), `ENOENT`
  or `ENOTDIR` (nothing there yet). Any other failure (`EMFILE` or `ENFILE`, since `ReadPlaceLink`'s `openat2` takes a
  descriptor, `ENOMEM`, `EIO`, `EACCES`) ends the placement, not placed, as `ELOOP` and `EINTR` did; before, an
  fd-exhausted read kept a symlink as a plain directory and placed the path at its spelling. The supervisor's fake
  kernel now tells `Readlink` (/proc only) from `PlaceLink`, so a placement wired back to `Readlink` fails the
  placement tests. Tests: `TestResolveUnixPlace` (each errno), `TestReadPlaceLinkRetriesEINTR`,
  `TestAskUnixPlacementEndsWhereTheAgentRacedADirectory`.
- 2026-10-19, R11c (continued): `agent.ReadPlaceLink` retries
  `EINTR` (a FUSE or network file system's lookup interrupted) up to 16 times, as the `os.Readlink` it replaced
  retried it, and a read still interrupted ends the placement, not placed, where the walk kept the unread name as if
  it were no link and could place the path where the kernel's lookup does not land. The bound R11c states is measured:
  1024 reads through plain directories 1100 deep take 35 to 56 ms, raced or not. Tests: `TestResolveUnixPlace` (an
  interrupted read is not placed), `TestResolveUnixPlaceIsBounded` (the plain-directory cell).
- 2026-10-19, R11c: a placement reads each name
  with the kernel's `PlaceLink` (`agent.ReadPlaceLink`: `openat2` of its directory with `RESOLVE_NO_SYMLINKS`, then
  `readlinkat`), where it read a `readlink` of the whole path. An agent's thread that made a name the walk had kept
  (nothing there yet) a symlink into a chain of 39 links through 780 directories and back made each later read follow
  it: 508 reads took 1.17 s for one placement, on the notification path, and through a link to a directory holding a
  dangling link the name was placed where that link points. Now the next read fails `ELOOP` and the placement ends,
  not placed (one read after the swap, 0.1 ms). Where `openat2` is refused (`ENOSYS`, `EPERM`) the read is the whole
  path's `readlink` again, its cost under such a race bounded only by the constants (1024 reads through up to 40
  links each; 1.46 s measured). `Readlink` reads /proc magic links only. Tests:
  `TestResolveUnixPlaceDoesNotFollowANameMadeALinkAfterItsRead`, `TestSysKernelPlaceLinkFollowsNoLinkBeforeItsName`,
  and `TestResolveUnixPlaceFollowsTheKernelsFortyLinks` (40 short links placed where the kernel's stat lands, 41
  refused as the kernel refuses them: the 40-link bound had no test once the 1024-name bound also ended the loop cell).
- 2026-10-19, R11c: `agent.ResolveUnixPlace` walks a path from
  the root one name at a time with one readlink per name, at most 1024 names and 40 links, where it resolved every
  prefix of each link's target from the deepest down with a whole-path `filepath.EvalSymlinks`: a connect by a chain of
  dangling links the agent made through hundreds of directories and back held a supervisor worker for seconds to tens
  of seconds (38 s for five links through 500 directories), on the notification path. A name past the bound is no
  scope's and is decided where it leads. A relative name whose directory is missing is placed from the cwd joined to the
  name uncleaned, where R6's lexically cleaned spelling was placed, so a `..` after a symlinked directory was applied
  before the link and the write entry admitted the name with nobody asked (`ENOENT`, no connect). `EvalSymlinks` now
  places only exec entries. The declared path's own lexical clean (compile's, every contract path's) is stated. Tests:
  `TestAskUnixPlacementOfAConnectsNameIsBounded`, `TestResolveUnixPlaceIsBounded` (real filesystem), three cells of
  `TestAskUnixScopeWhoseSocketIsNotThereYet`, and two cells of `TestIntegrationAskUnixScopeSpellings` (also in
  `TestRootAskUnix`).
- 2026-10-19, R11c: `agent.ResolveUnixPlace` walks the path and
  each link's target component by component, a `..` applied after the symlink before it is followed, where it joined a
  dangling link's target and cleaned it lexically: `s -> sub/../x.sock` with `sub -> real/deep` was placed at `x.sock`
  beside `s`, not `real/x.sock`, and an approval connected a listener there that the declared path never leads to.
  A connect whose last component is a symlink that leads nowhere yet is placed where that link leads, where it was
  placed at the link: the scope's own name as such a link was admitted by the write entry around it with nobody asked
  (`ENOENT`, no connect), or refused `unmatched` outside one; and a name whose directory does not exist yet is also
  the scope's when, placed as a scope is, it lands at the scope's place (a symlinked directory before the missing
  one), where only its spelling was compared. Tests: `TestResolveUnixPlaceFollowsALinkBeforeItsDotDot`
  (real filesystem, checked against `realpath -m`), `TestAskUnixScopeThroughALinkWithDotDot`,
  `TestAskUnixScopeNamedByALinkThatLeadsNowhere`, the symlinked-directory cell of
  `TestAskUnixScopeWhoseSocketIsNotThereYet`, and two cells of `TestIntegrationAskUnixScopeSpellings` (also in
  `TestRootAskUnix`).
- 2026-10-19, R11c (replaces the earlier scope
  rules): a pathname scope is a place (`agent.ResolveUnixPlace`, which also follows a
  symlink whose target the run makes later), and a connect is asked when its name reaches that place, by any spelling,
  where it was matched by the spelling passed: a relative or `getcwd` name in a project reached through a symlink was
  refused `unix-ask-scope` with nobody asked, and a scope through a symlink that led nowhere at start was refused
  `unmatched` once approved. A name that reaches another place is decided there: the run's own socket under a hard link
  or a new name is the write entry's, where earlier versions refused it `unix-ask-scope` by marks taken at its binds and
  decisions (`scopeMark`, `UNIX_DIAG_NAME`, `unix-ask-scope-unread`, all removed); a socket outside the run is refused
  `unix-foreign` there; an approved name the agent repoints during the wait is decided where it leads, where it was
  refused `unmatched`. A scope's place reached unasked (a datagram, a name repointed between the two walks) is refused
  `unix-ask-scope`.
- 2026-10-19, R11c: an approved connect the run's kernel then refuses (a lapsed
  one-connect grant) is recorded as the kernel's refusal or `observed`, an abstract unix name `observed` on `EPERM`
  or `EACCES`, where it was recorded allow with `authority: human`.
- 2026-10-19, R11c added: a unix connect a `net.ask` `unix:` scope names is held for a person and, once
  approved, relayed by R11 to the socket the scope resolved to; it was refused `unmatched`, and compile refused the
  scope. At tiers 2 and 3 an approved abstract name is admitted in the kernel by a one-connect grant (`GrantUnix`).
- 2026-10-19, R15b: a name-making end (`LookupParent`: an
  `unlink*`, `rmdir`, `mkdir*`, `mknod*`, `symlink*`'s new name, both ends of a `rename*`, a `link*`'s new name) ending
  in `/` lands at its directory's walk joined with the name, never where a final symlink leads, as `filename_parentat`
  and `lookup_one_qstr_excl` act on it; `FSTarget` took the whole walk for every end ending in `/`, a rule of
  `path_lookupat` ends only. The run decided `rmdir out/lk/` (`out/lk -> ../b/sub`) on `b/sub` and wrote `refused,
  unmatched` where the kernel answers `ENOTDIR` under the `out/` write entry, and `rmdir ro/lk/` (`ro/lk -> ../out/sub`)
  `allow` where Landlock refuses it `EACCES`; `compile --test`, asking the same walk with its prediction, followed a
  dangling `out/dl/` to its target and answered `refused` where the run allows. Tests:
  `TestNameEndEndingInSlashIsTheNameInItsDirectory` (the kernel's answers, and `Land` and `FSTarget` held to them),
  `TestANameEndEndingInSlashIsDecidedOnTheName` (each handler's line, real walks), `TestCompileLandsWhereTheRunLands`'
  generator now ending a fifth of its filesystem rows in `/`, `TestEveryRowEndIsWalkedAsItsSyscall` with each end also
  spelled with a slash, golden rows 18 to 21 of `compile-test-kernel-walk`, and the conformance cell
  `fs/rmdir-symlink-spelled-with-slash-into-write-entry`, whose effect judge no longer follows a name-making end's
  final link before a slash either.
- 2026-10-19, R15b: the
  lookup each end makes is one `agent.Lookup` (follow, create, no-follow, parent), from which every handler builds the
  end's walk (`pathQuery.as`) and with which `compile --test` lands a row's end (`agent.ActionKind.Lookups`, `Land`);
  no behaviour of the run changes. The run's handlers had written their lookup bits out one by one, compile's
  `Lander` took a single `follow` that `Land` read as both "not followed" and "name-making", and a `link*`'s old name,
  which the run walks whole and unfollowed since 2026-10-19, was asked by compile as a name-making end. Every site that
  decides, scores or names an end by its walk was reverted to the spelling in turn; each one no test caught (the fs.ask
  scope match made when the pin of an open fails, `settleFS`'s gate score of each end, `matchEnds`' landing match,
  `listenerRefuses`, `handOver`'s key, a held open's copied-name score and a delivered nameless held open's name, now
  `heldName`) is pinned by a test that fails with it reverted.
- 2026-10-19, R15b, R15c, R16b: an end a line names by
  its walk is decided there too, and a final `.` or `..` is walked whatever the syscall does with a final symlink.
  R15c and R15d matched every end as spelled first, so a `..` end's lexical clean, a file no mechanism decides on, was
  refused under a target on a line naming the file reached (`refused b/.git/config, rule
  fs.deny_write[out/.git/config]`, where `compile --test` answers unmatched); the held-direct open matched its copied
  name so too. `matchEnds` now takes such an end by its name; a failed walk that named the end decides there
  (`decideFS`), the gate scores it there (`landed`), an fs.ask scope with no held object, an exec and a loader's program are decided on
  the line's name, a walk-named open takes this loop's walk before a held open's pin, and a held open's line with
  no pin names it by that walk (`memoName`). `FSTarget` answered `EINVAL` with no walk for any unfollowed final `.` or
  `..`, which only the name-making families refuse before a lookup (`pathQuery.parent`); an attribute change with
  `AT_SYMLINK_NOFOLLOW` of `out/lk/..` read `allow, rule fs.write[./out/]` for a change of the directory above where
  `out/lk` leads, outside every write entry, and with a plane deciding the run R15c's refusal of a target reached so was
  skipped while the plane's hook refused it. A final `.` is named by the walk too (`walkNamed`): `out/lk/.` named the
  symlink `out/lk`.
- 2026-10-19, R15b, R16, R16b: a `..` end's name is
  taken from the walk that decides it, never from a second walk. An earlier fix named an end the syscall follows (an
  open, an exec, an attribute change, a followed link source) by a second walk of its directory, made apart from the
  decision's; an agent that moved a symlink between the two had its lines name a file the verdict was never taken on
  ("allow b/f, rule fs.write[./out/]" for a file outside every write entry, about 240 of 1500 opens at tier landlock),
  and an exec's line name the declared MCP server's file for the agent's own image, with an `mcp` line for a server
  that never started. The component walk now keeps the name as it passes the directory of the final component
  (`execWalk.named`): `FSTarget` answers it with the landing (`fsLanding`), `ExecImage` with the image
  (`execImage.name`), and `lineName` reads the decision's memo; an ask's refusal made once the open is held names it by
  the pin's own walk, the walk it was decided on (`askLineName`). An MCP start is matched on the image's identity
  before the name. Decisions are unchanged.
- 2026-10-19, R15b, R16b: a `..` end is named at the physical walk of its directory joined with its final component as
  spelled, never at its fully followed walk. An earlier rule named it where its own walk landed, so a final symlink was
  followed for the name: `out/realbin/sub/../ln` named `out/realbin/e`, and an exec of `./tools/../tools/mcpsrv`
  (`mcpsrv` a symlink to the server) named the server's target and wrote no `mcp` line, so drift read a server that ran
  as one that never started. An MCP start is now also matched on the image's identity (`mcpServerOf`). A refused
  rename's or link's `..` new name, which no decision walked, named the cleaned spelling; it is now walked for its
  name. Every name is walked before the answer. Tests pin each line that takes the rule: settleFS's, the handover's
  `Path` and `Path2`, the ask, gate and held-open refusals' (`TestRefusalLinesNameWhereADotDotSpellingLands`), and the
  exec line's.
- 2026-10-19, R15b, R16b: a line names the file its syscall
  reached where the pathname holds a `..` component. R6's lexical clean of the join named another file once a `..`
  followed a symlink: with `out/lk -> realbin/sub`, `unlink("out/lk/../e")` removed `out/realbin/e` and its line read
  `unlink out/e`, a file still there; `RENAME_EXCHANGE` of `out/lk/../e` and `out/e` read as an exchange of `out/e`
  with itself; and an exec of `/usr/bin/link/../python3` that loaded `/tmp/evil/python3` read as a refusal of the
  granted `/usr/bin/python3`. The verdicts were already the walk's; only the names were wrong. Such an end (an fs
  line's `path` or `path2`, the handover's naming of a kernel recorder's line, an exec line's `path` and its MCP
  server's match) is now named where its own walk landed it, when one was made and succeeded; any other spelling is
  recorded as before (`TestFSLineNamesWhereADotDotSpellingLands`, `TestExecLineNamesWhereADotDotSpellingLands`).
- 2026-10-19, R11, R11a (ADR 0019's note of that
  date): `LandUnix` answers for the tree the agent calls in and says whether what the name reaches is a socket
  (`agent.UnixLanding`): one already there, or the one the agent binds at a final name that names nothing yet and that
  nothing needs as a directory. A directory, made (`execWalk.madeDir`, which replaces `missingDir`: a name ending in
  `/`, `/.` or `/..` beyond what exists, or a made part the walk went beneath before it ended on it) or already there,
  and a file that is not a socket are none, and compile refuses them `unix-foreign` as `boundByRun` does; the `ENOTDIR`
  answer of the note below is gone. The run's own steps of R11's decision are functions `compile --test`'s property
  test calls as the run calls them: `decideUnixName` (decideUnix's name step), `landedVerdict` (decideLanded's
  decision), `unixAdmit` (the relay's admit) and `unixConnectLine` (finishUnix's verdict); `ruleUnixForeign` is
  `agent.UnixForeignRule`. No run's decision changed (`TestResolveActionFollowsAsTheKernel`,
  `TestCompileLandsWhereTheRunLands`, which now holds every generated unix row's verdict to these functions).
- 2026-10-19, R11, R11a: `predictUnix`
  answers a name whose missing part lies on procfs as a landing there (`errUnixProcfs`): what appears on procfs while
  the agent runs (`/proc/<pid>/fd/N`, `/proc/<pid>`, `task/<tid>`) is a magic link or a procfs directory, which
  `unixWalk` refuses, and compile's own entries there are not the agent's; it answered `ENOENT`, so a name through
  `/proc/self/fd/N` read as compile itself held N or not. A missing name ending in `/` or `/.` (`execWalk.missingDir`,
  in the spelling or a final link's body) is answered `ENOTDIR`, as the run's lookup fails it whether the socket is
  missing or bound (replaced by the entry above: it ends on the directory the agent makes); the walk keeps which made parts it went beneath (`virtKey`), so a name that comes back to one ends
  on that directory. `landFollowFacts` lets a test hold `predictUnix` to another follower's `fs.protected_symlinks`
  answer. No run's decision changed (`TestResolveActionFollowsAsTheKernel`, `TestCompileLandsWhereTheRunLands`,
  `TestLandUnixStepwise`).
- 2026-10-19, R11, R11a, R13b: `unixWalk` also answers
  `compile --test`'s connect and datagram names (`LandUnix`, ADR 0019's second 2026-10-19 note): the walk as R11 makes
  it, in compile's own view, classed by this loop's own answers to a failed walk (`unixLandedRefusal`,
  `unixWalkOutcome`); a name that does not exist yet is walked as `pathQuery.predict` walks a filesystem row's, with
  every magic link refused, each followed link held to `fs.protected_symlinks` and `nosymfollow` as the kernel's lookup
  holds it, and a missing part on procfs, where nothing is made, answered `ENOENT` (corrected by the next entry).
  The two rule names `path-unreliable`
  and `unix-absent` are `agent`'s constants, and `kernelRefusal`'s canonical-spelling test is `agent.UnixCanonical`, the
  one the decision core's `cgroup` and `bpflsm` columns ask. No run's decision changed
  (`TestResolveActionFollowsAsTheKernel`, `TestCompileLandsWhereTheRunLands`).
- 2026-10-19, R16b (ADR 0048 P2, K4): runs are pinned (command rules or an exec gate, at a plane tier). A pinned
  exec this loop would continue while no kernel recorder reads the run is refused `exec.pin` with `pin_unavailable`;
  the MCP start line of an exec whose line the kernel owns is the recorder's alone.
- 2026-10-19, R16b (ADR 0048 P2, K3): a pinned run's continued exec carries its pin, and one whose pin cannot be
  written is refused `exec.pin` with `pin_unavailable`.
- 2026-10-17, R15: R15's amendment of the same day said a walk "that cannot say where the
  path lands" is refused under `path-unreliable` at tier 2 with no plane mode; those are `decideFS`'s words for the
  `errOtherView` arm (a nameless object, or a file linked elsewhere), which never reaches `fallbackMutation` and is
  continued. R15 now names the refused walk failures (`EMFILE`, `ENOMEM`, `EIO`, `EXDEV`) and the continued
  `errOtherView` outcome apart (`TestFallbackMutationWalkFailures`, `TestR15NamesTheFallbackMutationRefusal`).
  No behaviour changed.
- 2026-10-17, R15 and who owns the line (ADR 0021 (5), ADR 0028 S3): R15 said a `deny_read`
  nested in a write entry "refuses no write" and that an unlink, rename, mkdir, symlink or link "keeps the Landlock
  verdict" at tier 2, and the owner list named only R15c's, R15d's and R5's refusals as this loop's. Since
  2026-10-04 the tier-2 verdict of a mutation is the root walk's, and with no plane mode `fallbackMutation` refuses
  it with `EACCES`; R15 says so in a dated amendment, and the owner list names it
  (`TestR15NamesTheFallbackMutationRefusal`, `TestFallbackMutationConverges`). No behaviour changed.
- 2026-10-17, R15b: `FSTarget` looks the parent of an end it does not follow up as a directory, as
  `filename_parentat` does: a name beneath a regular file is `ENOTDIR`, the task's own answer, where the walk landed it
  beneath the file. The same walk answers `compile --test`'s rows (`Land`, ADR 0019's 2026-10-17 note),
  asked of the tree before the agent runs: a component that does not exist yet is taken as a directory the agent makes
  later (`pathQuery.predict`), which the run's own walks never set. A path that lands on its own spelling and was
  named by an entry declared through a link (the agent replaced the link with a real directory, whose contents
  Landlock grants by another entry) is named by the entries where they are bound, the resolved table, when that
  answers the same verdict (`TestLineInAReplacedWriteLinkNamesTheGrantingEntry`).
- 2026-10-17, R15b, R17: each end of a rename or a link is decided where
  its own walk landed it, found by its query, never by its cleaned spelling. A new name `out/lk/../x` cleans to the
  source's `out/x`, so the destination's landing was looked up as the source's, the no-gain rule compared a
  directory with itself, and the line said `allow` for a move or a link the kernel refused with `EXDEV` (the kernel
  walks `out/lk/..` physically). The gate's facts and the handover's names are found the same way
  (`TestMoveEndsAreLandedByTheirOwnWalk`).
- 2026-10-17, R17: a hard link's line is taken as Landlock's
  `hook_path_link` decides it (both directories, never the file; the file rights gained at the new name's directory),
  and both no-gain rules count the rights the ruleset grants, an exec grant's `EXECUTE` included, so the line no
  longer says `allow` for a link or rename the kernel refused with `EXDEV`.
- 2026-10-17, R17: a rename's no-gain rule is asked as `hook_path_rename` asks
  it: not within one directory, the new name's directory against the moved object across directories (never the rule
  of the name it replaces), file rights only for an object that is no directory; the replace of an `exec.allow` file
  entry inside a write entry is no longer recorded `refused` while Landlock allowed it.
- 2026-10-17, R16b: an anonymous image the run does not admit is refused
  before the fast handover, `exec-anon`, as at tier 1.
- 2026-10-17, R16b: a directory entry grants an exec only while its resolved path
  holds the directory the loop stat'ed before the agent ran; an exec beneath a fresh directory made at the declared
  name is refused by this loop, as the kernel refuses it, where the line said `allow`.
- 2026-10-17, R17: the no-gain rule asks the exec grants by the inodes the
  builder held, wherever they are now, and takes a rename's and a link's ends as the names the syscalls act on, a
  symlink entry's own name unfollowed; the line no longer says `allow` for an `EXDEV` after the agent moved an
  `exec.allow` directory, nor `refused` for a symlink entry's atomic swap.
- 2026-10-16, R1, R5, R17 (ADR 0041 Step 2): an `fs.write` gate sees and scores
  the xattr and `chown` families as it scores a chmod (a POSIX ACL set through `setxattr` changed a mode outside the
  worktree the gate refused to `chmod`); a mknod is scored with the write predicates only (a read gate refused
  `mkfifo x.env`); and R5's fail-closed answer refuses a rename or link under a read gate alone, whose source the gate
  scores.
- 2026-10-06, R15c, R16b: the 2026-09-30 R15c, R16b entry below is history; both of its "not"s
  were lifted: the fs drop's gate opened at enforce-plane §2.15, and the exec hand-over to the plane was built on
  2026-10-04 (enforce-plane §2.19). Where the plane, both exec-exit hooks, the naming callback and a live recorder
  are ready, this loop's exec notification captures the attempt's metadata (`ContinuedExec`, `ExecNaming`) and
  decides nothing; where any of them is not ready, this loop keeps the exec's decision and line. *Corrected
  2026-10-16:* the note named no exception, and there is one. With exec command rules or an exec gate
  the fast hand-over is off until the exec is decided (`exec.go`, R16b's ADR 0048 (3) amendment): this loop
  decides first (the argv rules, the gate) and writes the line of what it refuses, and for what it continues,
  where everything above is ready, the kernel's line is the terminal one (`terminalOwned`) and this loop writes
  none. And since 2026-10-16 an exec whose pathname names nothing is answered by this loop with its walk's errno
  before either path, in every run, as no line (R16b (0), `missedExec`).
- 2026-10-05, R17: an `fs.write` gate sees the chmod family at every record level; the
  filter notified it under `record: full` only, so the gate's verdict on a chmod depended on the record level.
- 2026-10-05, R1: the table's numbers are checked against x/sys's per name, and a duplicate number panics.
- 2026-10-05, R3: an ask-scoped `connect` and an allowed IP `bind` whose address read came up short
  answer `EFAULT`, the ask unprompted; both used the readable prefix, so a bind succeeded and an approved connect
  connected where the target's own call faults (`TestAskConnectAnswersEFAULTForAShortAddress`,
  `TestBindAnswersTheKernelsAddressErrors`).
- 2026-09-30, R3: an allowed relay whose address read came up short answers `EFAULT`; it connected
  or sent with the readable prefix (`TestRelayAnswersEFAULTForAShortAddress`).
- 2026-09-30, R25 (e): the final fail-closed answer for an unanswered notification runs under its
  own recover; a second panic there ended the process.
- 2026-09-30, R12: a relayed stream `sendmsg` stops at the first `iovec` that faults and sends
  that prefix; it sent the later ones too. An `msg_iovlen` past 1024 is answered `EMSGSIZE`; it was cut and sent.
- 2026-09-30, R7: a connect whose address is shorter than its family's keeps this loop's line; the
  hook no longer records it (`TestKernelRecordsNeedsTheFamilysAddress`).
- 2026-09-30, R16b: an exec whose walk failed other than as the task's lookup would (`EMFILE`,
  `ENFILE`, `ENOMEM`, `EIO`, `EXDEV`) matches no grant by its spelling and is refused `path-unreliable`; it was
  continued as `allow` on the unverified spelling.
- 2026-09-30, R28, R16b: an exec pathname with a `..` component is not a PATH-search candidate; one
  that cleaned into a candidate was recorded as the search's probe of a file elsewhere.
- 2026-09-30, R16: an exec whose join to the cwd or dirfd R6 cannot make is recorded by the file the
  walk reached; its line named `""` or a relative path.
- 2026-09-30, R15, R15c: an `O_PATH` open with write-looking bits is a read; `O_PATH|O_WRONLY` on a
  `deny_write` target was refused and recorded as a write-open though the kernel writes nothing.
- 2026-09-30, R5: a rename or link whose second end has no spelling (a join over `PATH_MAX`) is
  recorded observed under `path-truncated`; with no `deny_write` target it was the source's allow with `path2` empty.
- 2026-09-30, R12: a relayed send's `EPIPE` without `MSG_NOSIGNAL` raises `SIGPIPE` on the
  trapping task; it hit this process's thread, which drops it, so the agent read a bare `EPIPE` (I3).
- 2026-09-30, R10: names the `handleConnect`/`relayUnix` contract; `handleUnixConnect` never existed.
- 2026-09-30, R33: a group missing from a fresh snapshot is scanned again only when its
  leader is in it; a bogus `kill(-N)` in a loop cost a whole-host `/proc` scan per call.
- 2026-09-30, R6: a `" (deleted)"` dirfd or cwd link is stripped only for a link count of 0, and a
  path joined to one is decided by the walk; the joined spelling could name another, live directory.
- 2026-09-30, R5: a `chmod`-family handler that panics or never answers is continued, not failed closed, save
  where a decision plane mode decides the run (`Options.PlaneAttrs`), where R15c refuses a chmod on a `deny_write` target.
- 2026-09-30, R15c, R16b (TIER3-PLAN T16): unchanged in effect. `Options.PlaneFS` turns the walk cache off for a run
  whose filter leaves fs mutations to the decision plane (enforce-plane §2.13, not yet enabled); the exec hand-over
  to the plane is not built (enforce-plane §2.13's condition 2).
- 2026-09-30, R33: a group scan that cannot read a process (not one that exited) refuses the
  signal; it skipped the process, so a launcher it could not read was left out and `kill(-its group)` continued.
- 2026-09-30, R33: `ioctl` is named a decision kind with the six; the rule counted six.
- 2026-09-30, R33, R35: a refused line names the group `kill(0)` and `PRIO_PGRP` 0 resolved to
  (it read `pid 0`) and a `PRIO_USER`/`IOPRIO_WHO_USER` uid (it read `every process (-1)`).
- 2026-09-30, R33: a `tkill`/`tgkill`/`rt_*sigqueueinfo` pid <= 0 is continued for the kernel;
  it was decided as process group 0, the host's kernel threads, and refused `EPERM` with a refused line.
- 2026-09-29, R25 (a): the own log's panic line carries the recovered stack, a relay goroutine's own for a relayed call.
- 2026-09-29, R17 (TIER3-PLAN T13): with a decision plane mode, a notified chmod beneath a `deny_write` target is
  refused here by R15c's predicate (`Options.PlaneAttrs`).
- 2026-10-05, R29: `relay-source-routed` (R9, ADR 0041 D6) joins the sentinels; the code emitted it, the list
  missed it.
- 2026-09-29, R29: `fd-exhausted` joins the sentinels.
- 2026-09-29, R25 (e): a panic in the recovery path's answer or gap line is contained and logged.
- 2026-09-29, R35 (new), R1: `prlimit64`, `setpriority`, the `sched_set*` calls and `ioprio_set` on another process
  are decided against the run's cgroup at every ABI.
- 2026-09-29, R15c, R15d: `DenyWriteTarget` is asked through the table's index too, the one index
  R15d's check uses (`decide.FSIndex`); by scan a question cost 9.5 ms against 50,000 targets.
- 2026-09-29, R15: the advisory tables, REFER's rule, the tier-2 listener's open decision and the exec grant are asked by index (`decide.AdvisoryList`, `FSIndex`), so a verdict costs the path's depth whatever the number of entries; a table the `.env` scan filled with 50,000 cost 2.6 to 44 ms per syscall by scan.
- 2026-09-29, R7 (tier 2): a refusing covering entry decides over the first declared (SEMANTICS §5).
- 2026-09-29, R13: a `sendto` with a zero `addrlen` is unaddressed and continued, as `sendmsg`'s
  zero `msg_namelen` is; it was refused as `args-unreadable`.
- 2026-09-29, R9 (thread pidfd note): below 6.9 the leader fallback checks the thread shares the
  leader's descriptor table (`kcmp` `KCMP_FILES`) and refuses as `fd-raced` otherwise; it duplicated the leader's file.
- 2026-09-29, R33: one `/proc` scan of the host's process groups answers group signals for 50 ms.
- 2026-09-29, R33: a `tkill`, `tgkill` or `rt_*sigqueueinfo` naming a pid of 0 or below is continued unread; it rescanned `/proc` per call.
- 2026-09-29, R33: the `ioctl` request is decided on its low 32 bits, as the filter and the kernel read it.
- 2026-09-29, R33, R2: the signal-scope reads are bracketed by `ID_VALID`; a refused line names the owner read.
- 2026-09-29, R7: with no `net:` section, no guard and `record: off`, an addressed connect or send takes no duplicate.
- 2026-09-29, R1: `sendmsg`/`sendmmsg` are notified on every call; the dispatch list names every entry.
- 2026-09-29, R3: an allowed relay with an `addrlen` the kernel refuses answers `EINVAL`, not the clamped call's result.
- 2026-09-29, R31: `op` restated to the recorded names; `umount2` records `umount`.
- 2026-10-16, R23a (new): a line's `mono_ns` is its notification's receipt, and a thread's lines are written in the
  order of its syscalls; a `PATH` search was recorded with later attempts before earlier ones. Amended the same day:
  an `ADDFD+SEND` answer orders the next notification as a `Send` does, and a lost order is counted in
  `run_end.supervisor.order_lost` and logged at `Warn`.
- 2026-10-19, R23a (beside ADR 0041 Stage B): the open deputy's `ADDFD+SEND` delivery of a held open
  sets the notification's `sent` flag before the ioctl, as the ask's completion and an alternate's delivery do, so
  the thread's next notification is ordered after the open's line.
- 2026-10-17, R22, R23a: the order wait parks on a channel after a few yields, not a 20 µs
  sleep poll, and is left out of the waiting notification's hold and slow count, which counted the previous one's
  emit a second time.
- 2026-10-19, R7a: where the plane decides the run's execs and the exec outcome
  links do not attach (5.14), the kernel's line of an allowed exec joins this loop's naming (`fileless`, `dropped`,
  argv), which only the outcome-linked line did; doctor's detail for the absent links says the supervisor decides
  every exec and a failed exec's errno is not recorded, not that it keeps exec ownership. Amended the same day:
  there too a supervisor-owned attempt drops the kernel's record, so an exec this loop
  recorded after a recorder failure is not written a second time by the final drain.
- 2026-10-19, R16b: an exec the floor did not allow is walked for what it loads and no
  further, and one with no line is not walked; ADR 0048's cost note said such execs read argv for their line anyway.
- 2026-10-17, R16b: `dropped` is one fact of the exec, judged once and
  copied by every owner of its line (this loop's line, the naming a kernel recorder's line takes, the fast handover's
  naming); in a run with command rules the `#!` chain and a loader's program are walked for every exec whose walk
  reached an image, whatever the image floor answers, so an observe run's would-be refusal that runs a binary it
  wrote is flagged. The command rules still decide only an exec the floor allows.
- 2026-10-17, R16b: in a run with command rules, an exec's `dropped` flag is also set
  when a `#!` interpreter of its chain or a directly-invoked loader's program was written during the run under a
  write entry; the text says that a run without command rules judges the exec's own image only.
- 2026-10-17, R23a: a parked order wait reuses the order book's waiters (channel and timer)
  instead of making both on every park; the text no longer calls the overlap rare on a loaded box, and says what the
  park cost (`BenchmarkSeccompNotifyRoundTrip` 14 to 15 allocs/op under load) and costs now (14).
- 2026-10-17, R16: with no `exec:` section, an exec under an enforced `deny_read` is
  judged where the kernel spells its image even when this loop cannot walk that spelling back to it, as
  `codex-home-exec` is; run through a descriptor from a directory the agent made unsearchable, it was recorded
  `allow` while Landlock refused it.
- 2026-10-17, R16b: an exec's `dropped` flag is judged where the kernel spells its
  image, confirmed here or not (`imageWhere`, as the `deny_read` and `codex-home-exec` arms judge); judged only on a
  confirmed spelling, a binary the run wrote, run through a descriptor from a directory the agent made unsearchable,
  carried no flag.
- 2026-09-29, R23: a full `Sink` waits up to its lane's bound, then drops; the response is already sent.
- 2026-09-29, R8, R27, R7, R28: `Loop.UpdatePolicy` removed; resolver freshness lives in `dns.Set`, the table
  is compiled once in `New`.
- 2026-09-29, R5: with no `net:` section and no `models[]` guard, an unreadable address or a socket that cannot be
  duplicated is continued and recorded `observed`, not refused.
- 2026-09-22, R1: x86-64 `rmdir` notified and dispatched; `open_by_handle_at` answered `ENOSYS` by the filter.
- 2026-09-22, R7: `AF_UNSPEC` in a send is refused; with no `net:`, connects are not
  relayed and `RESOLVE_UNIX` is unhandled at every ABI.
- 2026-09-22, R20 (fail-closed): a nested run fails at startup; routing to the ancestor's `Loop` is a condition.
- 2026-09-23, R7: the `models[]` guard; resolved-address refusals cover every
  class and admitting entry; admitted datagrams relayed; unspecified addresses match every guarded endpoint.
- 2026-09-23, R7, R12, R13b: `MSG_ZEROCOPY` refused on a relayed send; unaddressed `MSG_FASTOPEN` and
  guarded unaddressed `sendmsg` relayed.
- 2026-09-23, R11: `ELOOP` refused `path-unreliable`; an absolute name from another mount tree checked; credentials
  refused only when they cannot be taken.
- 2026-09-23, R15b, R15c, R5 (3): refusals re-taken where the path lands; built-in `deny_write` refused
  here; an unreadable pathname fails closed in such a run.
- 2026-09-23, R16, R16b, R28: every exec decided here; memfd arms on every kernel; PATH-search
  candidates answered, never continued.
- 2026-09-24, R1 (ADR 0018): unhandled notification answered `ENOSYS`; `socket`/`socketpair` dispatched.
- 2026-09-24, R15 (ADR 0016 step 1): Landlock
  union verdict; tier-2 write-open under `deny_read` refused; unlink/rename at the parent; exec-grant reads.
- 2026-09-24, R15b: spelling matched under declared and resolved entry paths.
- 2026-09-24, R15d: link or rename out of an unenforced `deny_read` refused at tier 2.
- 2026-09-24, R16b: file entry matched by inode and resolved path, in
  the supervisor's own mount view.
- 2026-09-24, R16b: a directory entry matched where the walk landed, not by the lexically cleaned spelling.
- 2026-09-29, R16b: a file entry with an identity matched where the walk landed too, not by the cleaned spelling.
- 2026-09-24, §4 `handleExecve`, R16: the answer is R16b's, not always `CONTINUE`; a hard link is not a grant.
- 2026-09-24, R33, R34: signal scope below ABI 6, `FIOSETOWN`/
  `SIOCSPGRP`; System V IPC refused unless `ipc: true`.
- 2026-09-24, R7 (one line per connect): a continued IP connect is the kernel recorder's line alone while it reads.
- 2026-09-24, R7: that line is named by this loop's own lookup (`Loop.ContinuedNet`): `net.resolver`, not `unmatched`.
- 2026-09-24, R7: a connect with `addrlen` 0 or 1 keeps this loop's line (the hook returns early for it);
  a decided recorder wins over a cancelled run (two lines were possible); `proto` follows `SO_PROTOCOL` as the
  hook's `sk_protocol` does, and a continued line's `dst` drops the scope id, so both lines spell a connect alike.
- 2026-09-28, R7, R15, R16, R17 (ADR 0028 S1): the advisory fs verdict and its tables are the decision core's
  (`decide.AdvisoryFS`, `decide.AdvisoryTables`), as are the predicates it shares with `compile --test`
  (`decide.Evaluate`, `ListenerOpenRefused`, `ExecReadGrant`, `PortAdmits`).
- 2026-09-29, R15b, R16b, R17 (ADR 0017 conformance): every fs verdict is taken where the path lands, observed when
  that is unknown; rename and link decided at both ends with `REFER`'s no-gain rule; a tier-2 exec the listener
  refuses reads refused.
- 2026-09-29, R15b: an end reached through no symlink, or resolvable in one `openat2` from the task's root, is not
  walked component by component.
- 2026-09-29, R15b: the walk cache answers an end in a scanned directory with no lookup, invalidated by every
  notified mutation and after 100 ms; R7a: the hand-over is keyed by the thread and the record's stamp, and an exec
  whose image's open the listener refuses has this loop's line alone.
- 2026-09-29, R17 (TIER3-PLAN T7): a mode change reads `allow` at tier bpflsm too, which now runs: its `path_chmod`
  is step B, so a refused line there recorded a refusal the kernel never made (`TestTruncateAndChmodLeaveOneLine`).
- 2026-09-29, R15c, R17: `truncate(2)` and the chmod family recorded (`op: truncate`, `op: chmod`); a truncate of a
  `deny_write` target refused.
- 2026-09-29, R7a (TIER3-PLAN T9): with the decision plane deciding the run's execs, a continued exec is the
  kernel's line (`Options.KernelExecs`).
- 2026-09-29, R15b: a pending mutation's thread is looked up at most once per 20 ms, outside the
  walk cache's lock.
- 2026-09-29, R7a: a `mknod` under a `deny_read` nested in a write entry keeps this loop's line,
  allowed under the write entry; the listener's write-open rule refused it and took a line the listener never wrote.
- 2026-09-29, R1, R15c: `mknod`/`mknodat` dispatched, recorded as a create, refused on a
  `deny_write` target; a unix `bind(2)`'s socket inode named as a residual.
- 2026-09-29, R2: an exec line's identity reads (`Tgid`, `ProcStat`) are followed by an `ID_VALID`;
  a notification gone by then writes no line.
- 2026-09-29, R15c, R15d: a relative name whose join is over `PATH_MAX` is refused under
  `path-truncated` by R15c and walked by R15d; both continued it.
- 2026-09-29, R15c: another case of a target's name on a case-insensitive file system is named as
  a residual.
- 2026-09-29, R15b: a `.` after a non-directory fails the walk `ENOTDIR`, as the kernel's lookup
  does; a final `.` skips both shortcuts and the walk cache.
- 2026-09-29, R16: argv is read only for an exec that writes a line.
- 2026-09-29, R15c, R15d: a modification whose walk fails other than as a lookup fails (`EMFILE`,
  `ENOMEM`, `EIO`) is refused under `path-unreliable`; it was continued. R15d asks the table's index, not a scan.
- 2026-09-29, R7a (new; ADR 0016 step 3, ADR 0017 conformance): one line per action at tier 2; the recorder owns
  the fs actions its hooks see, named by this loop where its index cannot; this loop owns its refusals, mode changes
  and execs; the listener its own refusals.
- 2026-09-29, R15 (ADR 0017 conformance): `watch` entries name the reads and refused modifications beneath them;
  an unenforced `deny_read` read at tier 1 carries compile's marker.
- 2026-09-30, R16: under `record: off` an exec observed for an unreadable pathname writes no line.
- 2026-09-30, R15b: an `O_NOFOLLOW` or `AT_SYMLINK_NOFOLLOW` pathname ending in `/` lands where a
  final symlink points, as the kernel follows it; it was decided at the link's own name.

## 6. Edge cases

1. **E1** target dies before the first `ID_VALID` succeeds: abandon, no response attempted, no event (R19).
2. **E2** target **dies** after a read but before `SEND`: `SEND`→`ENOENT`, swallowed; already-read data may still back an event. A stale id does not by itself mean the target died — see E35 for the other reason, which needs a different answer.
3. **E3** pid reuse between `NOTIF_RECV` and a memory read *or a `/proc/<pid>` magic-symlink read* (E9b): only `ID_VALID` bracketing (keyed by notification `id`, not pid) prevents reading the wrong process's memory (R2). `exec_id`'s own `start-boot-ns` component (§4 handleExecve) is only tick-resolution (~10 ms typically), so it is not itself a reliable pid-reuse discriminator at higher rates — `ID_VALID` bracketing, not the id string, is what correctness here actually relies on.
4. **E4** corrupt/oversized `ss_family`/`addrlen`: clamp to `sizeof(sockaddr_storage)`; unknown family → `unmatched` → refused, never a crash. `AF_UNSPEC` is excluded from "unknown" by R4's carve-out — but only in `connect(2)`, and only when the buffer really carried a family: a buffer too short to hold one reads as family 0 without being an `AF_UNSPEC` address, and stays unreadable/refused. In a send, `AF_UNSPEC` is unknown like any other family (R4). Under a `net:` section an unknown family in a send is refused with R10's errno, never `CONTINUE`d under R13b, whose best effort is for an address this tier read and matched; under a contract with no `net:` section it is `CONTINUE`d, since nothing is matched there (R7), except `AF_UNSPEC`, which is refused in either case (R4, R7), and except on an IP socket under the `models[]` guard, where it is refused as under a `net:` section (R7). Refused: `sendto`/`sendmsg` refuse it whatever the socket's type, connected or not, and `sendmmsg` refuses the whole batch on every socket type when any message up to the kernel's `UIO_MAXIOV` clamp (1024) carries one, not only among the first 64 (R13b). On a connected stream socket that is a deliberate cost, listed under R4: the kernel would have ignored the address (or, under `MSG_FASTOPEN`, failed the send itself). The refusal names the socket's own `proto` — the socket is read for the record only, and one that cannot be read makes the line `fd-raced` (§9); `connect(2)` with an unknown family is recorded the same way.
5. **E5** abstract unix name with embedded NUL bytes: matched by `socklen`-bounded raw bytes, never NUL-scanned (R11).
6. **E6** resolved relative-unix-path concatenation exceeds `PATH_MAX`: unmatched/refused; a Go-string logic decision, not a memory-safety issue.
7. **E7** `dirfd == AT_FDCWD` (-100): resolved via `/proc/<pid>/cwd`, never `/proc/<pid>/fd/-100`.
8. **E8** dirfd's directory was itself unlinked: `readlink` returns a `" (deleted)"`-suffixed target, detected and marked unreliable rather than concatenated verbatim. A live directory can carry that name too (the agent names entries inside its write entries), so only a link count of 0 on the dirfd (a `stat` through the same `/proc` link, inside the same `ID_VALID` bracket) strips the suffix, and the relative path is decided by the walk from the dirfd, never by its spelling (R6). The same test applies to `linkat`'s `AT_EMPTY_PATH` end.
9. **E9** dirfd number closed and reused by the target between trap and (async) read: `readlink` can silently resolve the *wrong* directory — acknowledged residual TOCTOU on the record only; Landlock still enforces the real fd. **E9b** the same `readlink` addressed by a `pid` the target no longer owns — target dead, `pid` recycled by an unrelated task — would root the recorded path in another process's `cwd`: prevented, not residual, by R2's `ID_VALID` re-check after the `readlink` (`reader.resolve`), which is E3's hazard in magic-symlink form. E9 stays residual because there the target is alive and only its descriptor moved, which no `ID_VALID` can see.
10. **E10** huge `argv` (e.g. `xargs`): truncated at 128 KiB, `argv_truncated: true`; the exec is decided on its
    pathname as any other (R16b), so an allowed one is still `CONTINUE`d.
11. **E11** adversarially large `argv` pointer array (memory-exhaustion attempt): capped at 8192 entries before any string is read, independent of the byte budget.
12. **E12** symlink loops via `/proc/<pid>/{cwd,fd/N,root}`: impossible — single-hop magic symlinks, no recursive resolution performed here.
13. **E13** non-UTF-8 bytes in a path/`argv` string: `encoding/json` substitutes U+FFFD silently (lossy, no error) — flagged gap (§11).
14. **E14** clock step (NTP, suspend/resume) mid-notification: `held_ms` uses monotonic-clock deltas only, never wall-clock subtraction (R24).
15. **E15** N concurrent `tego run` processes on one host: every `Loop` field is instance-scoped, no package/global state; `Loop`s never observe each other.
16. **E16** a run nested inside a run whose filter chain has a listener fails at startup with `EBUSY` (`launch.ErrChildSeccomp`, exit 125) and never reaches the ancestor's `Loop` (R20). Deciding the nested run's notifications at the ancestor's `Loop` against the ancestor's own, possibly broader, `Policy` would widen the nested contract, so the fail-closed start is the rule until R20's condition is met (§11).
17. **E17** worker-pool exhaustion under a build-like workload (~8k write/mkdir for an `npm install`): expected, not a failure; agent threads see the latency. ARCHITECTURE §15's 4–8µs a notification (~0.15–0.25s for 30k) is the 2026-09-22 design baseline's estimate, written before any supervisor code existed, and no benchmark of an fs notification reproduces it: the loop's own work, with the target's reads and the answer faked, is 1–10µs (the corrections' "Measured fast path"; R15b), and an fs open's round trip over a real listener is 45–52µs in the 6.17 guest on a quiet host (R15b). Measured end to end, kill test 5 found 60–280µs of run time for each notification an `fs.ask` entry keeps at tiers cgroup and bpflsm, in the kernel matrix's 2-vCPU KVM guests on a host other jobs' guests shared: ~0.5–2s for 8k and ~2–8s for 30k (ARCHITECTURE §15, amended 2026-10-06). These figures are about handlers measured in microseconds; a parked relay is a different shape and is covered by R21's standby rule, not by this one. *Amended 2026-10-16 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) §Performance, Stage B):* the Stage B budget restates E17 for held opens as 30,000 held read-opens in at most 1 s of wall time across the default four workers on an idle box; `BenchmarkHeldOpen` measured 0.93–3.7 s on a shared host, and 1.25 s (tier landlock's path) and 1.83 s (the root tiers', `BenchmarkHeldOpenRootTier`) in a 6.17 KVM guest whose host stole none of its CPU time: TARGET-MISS, one reason `gate.completion: held` is an opt-in (R22's 2026-10-16 note).
18. **E18** `process_vm_readv` → `EPERM` (Yama denies cross-memory access): `/proc/<pid>/mem` fallback fails identically (same `ptrace_may_access` check) — a supervisor/target identity mismatch `doctor` should already have caught; fail closed per R5, log distinctly.
19. **E19** partial (`EFAULT`-truncated) read mid-buffer: any short read is truncation of what was read, not an error, unless zero bytes were read with `ID_VALID` still true (bogus pointer) — then empty/marked-truncated, `CONTINUE` for record paths, `-EACCES` for connects (R5).
20. **E20** a path pointer with no NUL within the scan bound: stop at 4097 bytes, mark invalid/truncated, `CONTINUE` (R3).
21. **E21** `openat2`/`open_by_handle_at`/`io_uring_*` notifications never arrive — refused at the BPF filter, no dispatch entry needed (R1); documented to prevent a phantom "missing handler" report.
22. **E22** two threads of one target notify concurrently: each is blocked in its own trap, so concurrency is strictly cross-thread; `Policy` reads are lock-free and race-free under it (I9).
23. **E23** `Options.Workers=1`: fully serializes handling; valid, just slower under load — not an error.
24. **E24** `ctx` cancellation while workers block in `NOTIF_RECV`: the ioctl doesn't observe `ctx`; `Run` closes `l.fd`, unblocking every pending/future `NOTIF_RECV`, then joins workers.
25. **E25** run ends (`cgroup.events populated=0`) mid-notification: the facade's drain must wait for `Loop.Run` to actually return before `Metrics()`/`ledger.Close`, so the count is complete and no `Sink` send races the close.
26. **E26** binary upgrade mid-run (rename-install): no effect on a live `Loop` — it keeps the old in-memory dispatch table from its own mapped inode; a new run after the rename is independent (VERSIONING §1, §5).
27. **E27** kernel below a required primitive: unreachable once tier 1 is selected — `doctor`'s self-test gates it before this package runs (the floor in code is 5.14.0, `internal/doctor` D1, set by `cgroup.kill` and `SECCOMP_ADDFD_FLAG_SEND`; it already has `NEW_LISTENER` 5.0, `SEND`+`CONTINUE` 5.5, `pidfd_getfd` 5.6).
28. **E28** sustained high notification rate: every `/proc/<pid>/mem` fallback fd is `defer`-closed right after its read; nothing cached across notifications, preventing fd exhaustion. The same holds for the R9/R12 `pidfd` (closed inside `duplicate`) and for the duplicate itself, which a handler closes before it returns unless a relay has taken it; a relay closes it when its syscall returns, possibly after its handler and `Run` have both returned. Outstanding duplicates are therefore at most one per running handler (`Workers + maxStandby`) plus one per live relay goroutine (capped at `Workers + maxStandby`, R21), however high the notification or signal rate. A relayed unix connect (R11) holds three descriptors more for as long as its relay does — `O_PATH` of the task's root and cwd, taken on the worker and handed to the relay with the duplicate, and the socket's own `O_PATH` while it is connected to — so the same ceiling bounds those at three per relay.
29. **E29** transient DNS failure during TTL refresh: stale `NetRule.Nets` is kept; a resolution error never empties a rule's IP set (R8a) — no spurious refusal.
30. **E30** symlink swapped into `cwd`'s chain between trap and `readlink` (race on the record, not enforcement): accepted advisory-only limitation, same class as E9.
31. **E31** obtaining a pidfd for the *notifying* pid before the R9/R12 duplicate (`pidfd_getfd(target_pidfd, sockfd, 0)` needs a `target_pidfd`, and the notification carries only `notif.pid`, an integer): opening that pidfd (`pidfd_open(notif.pid)` or via `/proc/<pid>`) is itself racy against pid reuse, the same class of race R2/I1 close for memory reads but never previously stated for this control flow — this package re-validates with `NOTIF_ID_VALID(id)` immediately before the duplicate's `connect()`/`sendto()` (extending R2 to the pidfd-acquire step). A stale pidfd's `connect()` either targets a socket `NOTIF_SEND` then rejects as stale (`ENOENT`, R19), or, on the residual window between the final `ID_VALID` and `NOTIF_SEND`, is an accepted TOCTOU of the same class as E9/E30.
32. **E32** `Policy.Resolver` is empty at run start (`/etc/resolv.conf` unreadable, or a systemd-resolved stub with no usable upstream listed): R14's "port 53 always allowed" exception then matches nothing, and DNS falls through to ordinary R7 host:port matching like any other destination — not a crash, not a default-allow; `resolver: auto` (spec/config/v0) documents the source but not this fallback.
33. **E33** `resolveSocket`'s `getsockopt(SOL_SOCKET, SO_TYPE)` (§4, for `sendDecisionCtl` and `handleConnect`) runs on a `pidfd_getfd` duplicate of an fd known only by number; the target can close and reuse that fd number for a socket of a different type between the trap and the duplicate, so the type read reflects the *new* file description. Same fd-number-reuse class as E9. A `SOCK_STREAM` misread as `SOCK_DGRAM` degrades a Fast-Open decision (R12, block-capable) to best-effort `CONTINUE` (R13b, the safer direction); the reverse misread is caught by R5 fail-closed if the subsequent read fails, and by the real `connect()`/`sendto()` errno (I3) otherwise. The deterministic variant — a secondary thread with a descriptor table of its own, duplicated through its leader's pidfd below Linux 6.9 — is not accepted: the fallback refuses it (R9's thread pidfd note).
34. **E34** a handler panics (e.g. a bounds bug in the `argv`/8192/128 KiB reader): recovered per-notification (R25), never a whole-worker or whole-process crash; sibling in-flight notifications on other workers are unaffected (I12).
35. **E35** the target **abandons** its syscall while a relayed `connect`/`sendto`/`sendmsg` is still running on the duplicate. A signal delivered to a target blocked in a notified syscall cancels the notification, and `seccomp_unotify(2)` ("Interaction with `SA_RESTART` signal handlers") is explicit about what follows: `NOTIF_SEND` fails `ENOENT`, "the kernel will restart the target's system call. Consequently, the supervisor will receive another user-space notification", and this "will occur even for the blocking system calls listed in signal(7) that would never normally be restarted by the `SA_RESTART` flag". Because R9/R12 perform the syscall **before** they answer, the side effect has already happened when that `ENOENT` arrives, and the restart does it a second time: the same bytes on the wire twice for a relayed send, `EISCONN`/`EALREADY` for a restarted connect, two `allow` lines in an append-only chain for one call the agent made once. It needs no attacker — `tego stop` sends `SIGTERM`, the child stage sets `PR_SET_PDEATHSIG`, and any agent using `SIGCHLD` or a profiler's `SIGALRM` reaches it. This is **not** E2: the target is alive and the run continues. The same man page states the supervisor's obligation — "when the supervisor wishes to emulate a blocking system call, it must do so in such a way that it gets informed if the target's system call is interrupted by a signal handler ... it could employ a separate thread that uses the `SECCOMP_IOCTL_NOTIF_ID_VALID` operation to check if the target is still blocked" — so a relay outstanding past `relayGrace` (2 ms) is polled with `ID_VALID` every `relayPoll` (20 ms). A stale answer marks the notification gone (R19: nothing to answer), counts `metrics.orphaned`, logs at `warn`, and **records the `net` event anyway** with the additive `result_unknown: true`: the connect is real and may already have opened the connection, so suppressing it would leave a connection this loop opened with no line in the ledger at all, and without the marker the duplicate the restart produces reads as a second connect the agent made. The residual — the side effect still happens twice — cannot be closed from this package; see the corrections below for the `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` change that closes it, which belongs to `internal/platform/sys` and is now made there: on a 5.19+ kernel a non-fatal signal no longer withdraws a received notification, so an orphaned relay there means the target was killed and nothing restarts — on a kernel carrying the 2025 fix `cce436aa` ("seccomp: Fix a race with WAIT_KILLABLE_RECV if the tracer replies too fast"). Without it one window stays open: a non-fatal signal that lands while the answer is being sent interrupts the target after `NOTIF_SEND` has succeeded, and the kernel restarts the syscall. Nothing here sees that — there is no `ENOENT` and no stale `ID_VALID` — so the relayed side effect happens twice with no `result_unknown` line and no count in `orphaned`. **Its cost, taken on purpose:** from the `RECV` until the answer the target's non-fatal signals wait, and for a relay that is the relay's whole duration, which has no deadline (§4) — up to the ~127 s SYN retry schedule against a blackholed route. A `SIGINT` the agent handles (a Python agent's Ctrl-C), a `SIGTERM` handler reached by `tego stop`, an `alarm()` timeout and `SIGSTOP` are all held until the relay returns; a fatal signal — `SIGKILL`, or one whose default action terminates and that has no handler — still ends the wait, and `tego stop` escalates to `cgroup.kill` after `stop_grace`. The alternative is the double side effect above; bounding the relay instead would need the deadline §4 does not give it and an answer I3 forbids inventing, so it is not done. Under a contract with no `net:` section nothing is relayed (R7), so nothing waits there, save an
IP connect or Fast-Open send under the `models[]` guard (R7).

**Changes.**
- 2026-09-22, E16 (fail-closed): a nested run fails at startup (R20).
- 2026-09-28, E27: the kernel floor is 5.14.0 in code (doctor D1), not 6.1.
- 2026-09-30, E33: the `SO_TYPE` read is `resolveSocket`'s; `handleSendAddr` never existed.
- 2026-09-29, E33: a thread with its own descriptor table is refused, not read through its leader's.
- 2026-09-30, E8: a live directory named `<x> (deleted)` keeps its name; the walk decides either case.
- 2026-10-06, E17 (kill test 5): the cost of a notification an `fs.ask` entry keeps is measured end to end, 60–280µs, in
  the matrix's 2-vCPU KVM guests on a shared host. The 4–8µs was the design baseline's estimate (2026-09-22, before any
  supervisor code existed), not an end-to-end measurement, and no benchmark of an fs notification reproduces it, so a
  build-like workload's 8k to 30k notifications cost about 0.5 to 8 s, not 0.15–0.25 s (ARCHITECTURE §15, amended the
  same day).

## 7. Failure modes and handling

| Failure | Detection | Response | Ledger | Event/exit | User sees |
|---|---|---|---|---|---|
| Target dies mid-notification | `ID_VALID`/`SEND` → `ENOENT` | abandon `notif`, no `NOTIF_SEND` retry | none, or a partial event if data was already read (R19) | none (this is normal process exit, not a run failure) | nothing; the agent's own exit path proceeds |
| `NOTIF_SEND` or `ID_VALID` fails with an errno other than `ENOENT` | the ioctl's errno (`EINTR` is retried in `internal/platform/sys`: `notify_lock` is taken interruptibly and the kernel does not restart it) | retried once; an `ID_VALID` still failing answers the notification fail-closed (R5) and abandons it, except under a relay, which keeps polling rather than invent a result (I3) | none beyond the handler's own line | none | at worst one fail-closed answer; never a task left trapped with no answer |
| Args unreadable (connect) | read error or zero-progress with `ID_VALID` still true | `-EACCES` (R10) — `CONTINUE` under a contract with no `net:` section and no `models[]` guard (R5) | `net verdict=refused reason=net-not-allowed rule=args-unreadable`; `observed`, `best_effort` with no `net:` section | none (not fatal to the run) | the agent's `connect()` fails with the R10 errno; reason file names `args-unreadable` |
| Args unreadable (record path) | same | `CONTINUE` — save an `fs` modification in a run whose built-in `deny_write` set is not empty, which R15c refuses with R10's errno: under the target's rule when another end reaches one, otherwise under the unread path's marker | `fs` event with empty/truncated `path`; an `exec` event with a truncated `argv`; for R15c's refusal, `fs verdict=refused rule=fs.deny_write[<target>]`, or `rule=args-unreadable`/`path-truncated`, under `record: off` too | none | nothing (op proceeds; Landlock's own decision is what the agent feels), or R15c's errno |
| An fs modification's walk fails other than as the task's lookup fails (R15b): `EMFILE`/`ENFILE`/`ENOMEM`/`EIO` in this process, or `EXDEV` | `FSTarget`'s errno, not one of `lookupFailure`'s | R10's errno in a run whose built-in `deny_write` set is not empty (R15c), and at tier 2 for a link or rename in a run with an unenforced `deny_read` (R15d), and for any modification in a run with a `deny_read` at tier 2 with no plane mode (R15's 2026-10-17 amendment, `fallbackMutation`; not a walk that reached an object with no path here, `errOtherView`, which is continued); otherwise the advisory verdict, `observed` where it was not a refusal | `fs verdict=refused rule=path-unreliable reason=<the operation's>`, under `record: off` too | none | R15c's errno on a write that may have reached a target |
| An exec's walk fails other than as the task's lookup fails (R16b): `EMFILE`/`ENFILE`/`ENOMEM`/`EIO` in this process, or `EXDEV` | `ExecImage`'s errno, not one of `execLookupFailure`'s | `-EACCES`, never `CONTINUE`: the spelling matches no grant — `CONTINUE` under a contract with no `exec:` section, save the R16 `deny_read` arm | `exec verdict=refused reason=exec-not-allowed rule=path-unreliable` (a PATH-search candidate stays `observed`, answered `-EACCES`); `allow rule=unmatched` with no `exec:` section | none | the agent's `execve` fails while this process cannot vouch for the walk |
| Exec pathname or descriptor unreadable | read error, a pathname past `PATH_MAX`, or `/proc/<tid>/fd/<dirfd>` unopenable | `-EACCES` (the lookup's own errno where it has one: `EFAULT` for a pathname whose read faults before its NUL, `ENAMETOOLONG` for one with no NUL in its first `PATH_MAX` bytes, as the kernel's getname answers, in every run with an `exec:` section since 2026-10-06, EFAULT before; `EBADF`) — `CONTINUE` under a contract with no `exec:` section | `exec verdict=refused reason=exec-not-allowed rule=args-unreadable` (or `path-unreliable`); `observed` with no `exec:` section | none | the agent's `execve` fails (R16b: an exec this loop cannot match is not continued) |
| Handler panics mid-decision | `recover()` in the worker's dispatch wrapper (R25) | best-effort fail-closed response if `id` is still valid — `-EACCES`/R10's errno, every kind alike, outside an observe run (R30, where it is `CONTINUE`) | `gap what=record why=handler-panic` (best-effort); recovered stack goes to the own log only, never the ledger | none (not fatal to the run) | no visible crash; worst case one incomplete/refused decision plus a debug-log line |
| `Policy` refresh (DNS) fails | resolver error in `dns.Set`'s TTL refresh | keep stale `Nets` (R8a, merge owned by `dns.Set` per R27) | optional `gap what=record why=dns-refresh-failed` (informational) | none | no visible change; a host does not start refusing without cause |
| Worker pool exhausted | notification queue depth (kernel-side, not directly observable) exceeds `Workers` | none — kernel backpressure on the target thread | none directly; contributes to `held_ms` | none | agent-visible latency on writes/execs during the burst |
| `Sink` full (ledger backpressure) | no room in the supervisor lane within its 250 ms wait | drop counter increments; response already sent; the worker's next notifications waited behind it | next opportunity: `gap what=record count=<n>` from the pipeline, not this package | none | none directly; `drift`/`events` shows a `gap` |
| Listener fd closed unexpectedly (supervisor crash elsewhere in the process) | poll reports `POLLNVAL`, or poll/`NOTIF_RECV` returns `EBADF`/`EINVAL`/`ECANCELED`, while `ctx` is live | `Run` returns an error; workers exit | `run_end reason=orphaned` written later by the sweep (not by this package — ARCHITECTURE §6) | orphan sweep on next `run`/`stop`/`gc` | the run appears stuck, then is swept; every notified syscall in the meantime returns `-ENOSYS` (fail-closed) |
| `pidfd_getfd` fails (target closed the fd first, a genuine race; or a non-dumpable target, `EPERM` at tier 1) | `pidfd_getfd` errno (`EBADF`, `EPERM`) | treat as connect data unreadable → R5 fail-closed; `CONTINUE` under a contract with no `net:` section and no `models[]` guard, save an `AF_UNSPEC` send (R5); a send carrying `MSG_MORE` in a run that decides datagrams is refused the same way, whatever its socket, a TCP one included, and so is one whose number now names no socket (`fd-raced`), as R13's pending frames read the socket for it (amended 2026-10-20); a `sendfile` or `splice` whose descriptor is not open (`EBADF`) is continued, the kernel's own `EBADF`; one whose descriptor cannot be duplicated otherwise, or whose type cannot be read, may be into a socket that holds frames and is refused, fail-closed, on a `refused` line, not a net line (amended 2026-10-20) | `net verdict=refused reason=net-not-allowed rule=fd-raced`, or `rule=fd-unreadable` for `EPERM` (amended 2026-10-20: no race happened), and for a thread whose descriptor table is not its leader's below 6.9 or a kernel with no `kcmp` (`ENOSYS`; amended 2026-10-20); `observed`, `best_effort` when continued; a `sendfile` or `splice`: `refused op=sendfile` (or `splice`) `target="fd <n>" reason=net-not-allowed`, the same rule, with no `proto` | none | the agent's `connect()` fails; a legitimately-racing close means the agent likely errors anyway. At tier 1 a process that made itself non-dumpable has every `connect` and addressed send refused under a `net:` section (R5), and, in a run that decides datagrams, every `sendfile` and `splice` it makes, whatever it copies into: a file copy (Python's `shutil`, Go's `File.ReadFrom`) fails `EACCES` (enforce-landlock R11d's cost) |
| `pidfd_open` or `pidfd_getfd` fails with `EMFILE`/`ENFILE` (this process's descriptor table, or the system's, is full: no race happened) | the errno, carried out of `duplicate` | as the row above: R5 fail-closed, `CONTINUE` where that row continues | `net verdict=refused reason=net-not-allowed rule=fd-exhausted`; `observed`, `best_effort` when continued; a `Warn` in the own log at most once per 10 s | none | every allowed `connect()`/Fast-Open send under a `net:` section fails until descriptors free up, and so does every send carrying `MSG_MORE` and every `sendfile` or `splice` in a run that decides datagrams, a TCP one included, whose socket R13's pending frames must read (amended 2026-10-20); the own log says why at the default level |
| Relay ceiling reached (R21: `Workers + maxStandby` relayed syscalls already outstanding, typically orphaned ones, E35) | the relay goroutine count, checked before a relay starts | the allowed connect / Fast-Open send is not performed; R10's errno | `net verdict=refused reason=net-not-allowed rule=relay-limit` | none | the agent's `connect()`/`sendto()` fails with the R10 errno until the kernel returns the outstanding syscalls; `metrics.relayLimited` and a `warn` line say why |
| A relay under a net gate or a `net:` section meets a source-routed IP socket (R9: `IP_OPTIONS` LSRR/SSRR or an `IPV6_RTHDR`), or its options or domain cannot be read | `getsockopt` on the duplicate before the relayed call; the filter refuses a `setsockopt` that would add one later (enforce-landlock R11b) | the admitted connect / Fast-Open send / datagram is not performed; R10's errno | `net verdict=refused reason=net-not-allowed rule=relay-source-routed` | none | the agent's call fails with the R10 errno; its `setsockopt` of those options fails `EPERM` |
| Under a `net:` section, a `sendmsg` or `sendmmsg` on an IP socket that is not a stream one carries a control message that routes its datagram (R13b: `IP_RETOPTS` or `IP_OPTIONS` at `SOL_IP`, `IPV6_RTHDR` or `IPV6_2292RTHDR` at `SOL_IPV6`), or a control buffer longer than `msgControlMax` | the control buffer read and walked before the decision, at most `msgControlMax` bytes a message | the call is not continued, a batch is refused whole; R10's errno | `net verdict=refused reason=net-not-allowed rule=relay-source-routed` | none | the agent's `sendmsg()`/`sendmmsg()` fails with the R10 errno |
| An operation could start or join a pending frame (R13's pending frames), in a run that decides datagrams: a `sendto`, `sendmsg` or `sendmmsg` carrying `MSG_MORE`, or a `sendfile` or `splice`, on a socket that can hold a frame (UDP, UDP-Lite, raw IP, or one whose domain cannot be read); a `setsockopt(UDP_CORK)`; a datagram this loop would send itself on a socket with `UDP_CORK` set or unreadable | the syscall's flags argument and setsockopt's level and option (registers); the socket's `SO_TYPE`, `SO_PROTOCOL`, `SO_DOMAIN` and `getsockopt(SOL_UDP, UDP_CORK)` on the duplicate | nothing is sent; R10's errno | `net verdict=refused reason=net-not-allowed rule=datagram-corked`; a cork's `refused op=setsockopt rule=datagram-corked` | none | the agent's call fails with the R10 errno |
| An approved datagram's relay succeeded at tier 2 or 3 but its credit was left untaken (R13d: it joined a pending frame, or a refresh admitted its destination meanwhile) | the revoke's report | the relayed result, as the kernel answered it | `net verdict=observed authority=human rule=<the scope's>` | none | the agent's call returns the relayed count |
| A relayed unix connect cannot be made as the task (R11): its `/proc/<tid>/status` or directories unreadable, or no thread can take its credentials (at tier 1: groups that differ from this process's, or an effective uid or gid that is none of its ids) | `TaskOf` / `sys.RunAs` error | not performed; R10's errno | `net verdict=refused reason=net-not-allowed rule=relay-credentials` | none | the agent's `connect()` fails with the R10 errno; never made with this process's credentials instead |
| A relayed unix connect's walk cannot be vouched for in this process's view (R11): `ELOOP` (a magic link the relay will not follow, or a loop), a relative name from a task with a root of its own, or a resolved path that reaches another inode here (a task in another mount tree) | `ConnectUnixAs` outcome | not performed; R10's errno | `net verdict=refused reason=net-not-allowed rule=path-unreliable` | none | the agent's `connect()` fails with the R10 errno; never decided on a path that names another file here |
| `connect()` on duplicate fails with a real network errno | the syscall's own return | relayed verbatim (R9) | `net verdict=allow` (the *policy* allowed it; the network itself refused) `rule=<matched>` | none | the agent sees the real `ECONNREFUSED`/`ENETUNREACH`/etc., indistinguishable from a run without Tego |
| Malformed notification data (fuzz-class input) | bounds checks in every reader (R3, R4, R20) | never panics observably; degrades to R5/E20-style safe defaults, or is caught by R25 if a bound check itself has a bug | best-effort event, possibly empty fields | none | no crash; worst case a slightly incomplete record line |
| Budget exceeded (slow notification) | `time.Since(recvAt) > budget` at respond time | none (soft) | none directly; feeds `held_ms` | none | none directly; visible only in `--log-level debug` and in `measure`'s overhead numbers |

**Changes.**
- 2026-10-17, fs walk fails: the row named R15c's and R15d's refusals
  only; at tier 2 with no plane mode `fallbackMutation` refuses such a walk under `path-unreliable` for any
  modification once the table has a `deny_read` (since 2026-10-04, ADR 0021 (5)). No behaviour changed.
- 2026-10-20, pending frame (ADR 0008's design note): the row is every operation
  that can start a frame, decided on the socket; a new row for an approved datagram whose credit the kernel left; the
  `fd-exhausted` and `fd-raced` rows name the sends and copies a pending-frame read can fail.
- 2026-10-20, `pidfd_getfd` fails: a secondary thread whose descriptor table is not its leader's
  (below 6.9, `errOwnFDTable`), or a kernel with no `kcmp`, is `fd-unreadable`, not `fd-raced`.
- 2026-10-20, `pidfd_getfd` fails: an `EPERM` (a non-dumpable target at tier 1) is
  `fd-unreadable`, not `fd-raced`, on every line that names it; a `sendfile` or `splice` whose descriptor could not be
  read is recorded on a `refused` line naming the call and the descriptor, not on a net line whose `proto` (`tcp`, the
  default) nobody read; and the consequence column says that such a process's file copies are refused.
- 2026-10-19, pending frame: UDP-Lite, and an unaddressed `sendmsg` or `sendmmsg`.
- 2026-10-19, pending frame (new row): the `datagram-corked` refusal.
- 2026-11-02, source-routed relay (GAPS C34): the row covers a relay under a `net:` section too, where the
  relayed connect followed the socket's route to a first hop no entry admits.
- 2026-11-02, routing control message (GAPS C34; new row): a datagram whose own control messages route it is
  refused under a `net:` section; the kernel sent it to the route's first hop.
- 2026-10-05, source-routed relay (new row): the `relay-source-routed` refusal, and the filter arm that
  keeps a sibling from adding a route after the read.
- 2026-09-30, exec walk fails (new row): refused under `path-unreliable`, never continued on the
  unverified spelling; it was continued `allow` when the spelling matched a grant.
- 2026-09-29, fs walk fails (new row): refused under `path-unreliable` where R15c or R15d has a
  target; it was continued.
- 2026-09-29, descriptor exhaustion (new row): `EMFILE`/`ENFILE` is `fd-exhausted`, logged at `Warn`, not `fd-raced`.
- 2026-09-29, listener closed unexpectedly: detected by `POLLNVAL` or a poll/`RECV` errno on a live `ctx`.
- 2026-09-29, `Sink` full: detected by the lane's 250 ms wait running out, not a non-blocking send.
- 2026-09-29, `Policy` refresh (DNS) fails: the refresh is `dns.Set`'s, not an external `UpdatePolicy` caller's.
- 2026-09-29, `NOTIF_SEND`/`ID_VALID` failures (new row): `EINTR` retried, other errnos retried once, never read as
  the target's death.
- 2026-09-29, args unreadable (connect), `pidfd_getfd` fails: continued and recorded `observed` under a contract with
  no `net:` section and no `models[]` guard (R5).

## 8. Invariants

- **I1** no target-memory/path read — a `/proc/<pid>` magic-symlink read included (E9b) — is used for a decision
  *or for the record* without an immediately-preceding `ID_VALID(id)` on that same `id` and another before the bytes
  are trusted (R2); the R9/R12 pidfd-acquire step is bracketed the same way (E31). I1 said "for a decision" before
  2026-09-22 — narrower than R2, and the only reading the record-only handlers then satisfied; R2 is the contract.
- **I2** outside an observe run (R30), a connect decision (TCP or unix, R7/R9/R10) is never answered with
  `CONTINUE`. In an observe run, every decided or fail-closed connect refusal — for example an unmatched
  destination, `relay-limit`, `relay-credentials`, `path-truncated`, `args-unreadable`, `fd-raced`, an unanswered
  or panicked handler — is answered `CONTINUE`, and only a relayed result keeps I3: an admitted connect, a
  Fast-Open send and R4's `AF_UNSPEC` carve-out are still performed on the duplicate and answered with their real
  result. The continue is deliberate, because that run
  enforces nothing, and R30 states its one cost (the recorded `dst` can differ from the one the kernel reads).
  `TestConnectIsNeverContinuedWhateverItDecides` pins the enforcing half; `TestObserveContinuesAConnectItWouldRefuse`,
  `TestObserveNeverFailsClosed` (args-unreadable), `TestObserveAnswersAnUnansweredDecisionWithContinue`,
  `TestObserveContinuesEveryFailClosedAnswer` (fd-raced, relay-limit, a panicked handler) and
  `TestObserveStillRelaysWhatItPerforms` (`AF_UNSPEC` and a Fast-Open send, relayed) pin the observe half.
  Under a contract with **no** `net:` section nothing is a connect decision — SEMANTICS §1 denies nothing there —
  and every connect is answered `CONTINUE` so the kernel performs it as the agent (R7 says why a relay must not);
  `TestConnectWithNoNetSection` and `TestIntegrationNoNetSection` pin it.
- **I3** an allowed connect's response always reflects the real `connect()`-on-duplicate result; never fabricated.
- **I4** a notification stays open pending a human answer only for an ask scope (held opens, R11c, R13d); no other
  response waits on a person.
- **I5** the worker loop never blocks `NOTIF_SEND` on `Sink` availability (R23); emit is strictly after respond.
- **I6** `connect()` on the duplicate always executes on the target's own socket (`pidfd_getfd` duplicates its own
  open file description, so its netns, its bound address and its cgroup's programs are the target's); never
  substituted. The checks `connect(2)` makes of the *calling task* are this process's unless the relay takes the
  task's: a pathname socket's DAC, the Landlock domain
  (none here), and the credentials the listener reads in `SO_PEERCRED`. For TCP and UDP R9 accepts that — the
  host was decided here, and the domain's port rules are only a backstop (enforce-landlock R6) — but for a unix
  socket a relay with this process's credentials would reach what the agent's uid could not, at tier 2 as root. R7
  therefore relays nothing under a contract with no `net:` section but an IP connect or Fast-Open send under the
  `models[]` guard, which has no pathname or abstract name for a credential to matter to. A relayed unix connect is
  made on a thread holding the calling task's groups, effective ids and at most its effective capabilities, on the
  socket its path resolves to as the task (R11), so the pathname socket's DAC and `SO_PEERCRED`'s uid and gid are
  the task's. `SO_PEERCRED`'s pid is still this process's (Open, below), and the thread has no Landlock domain:
  below ABI 9 the domain checks no pathname socket, R11's decision on the resolved socket stands in for
  `RESOLVE_UNIX` at ABI ≥ 9, and the abstract scope must not apply, since the relay is how a declared abstract name
  reaches a listener outside it (enforce-landlock R7).
- **I7** `metrics.notifications`/`heldMS` are monotonically non-decreasing for one `Loop`'s life; `Metrics()` is read
  exactly once per run, after `Run` fully returns.
- **I8** the dispatch table is fixed at `New()` from a compile-time per-`GOARCH` table; no syscall number is ever
  looked up from untrusted or runtime data.
- **I9** every `Policy` read is a single atomic load of a fully-constructed, immutable value; no partially-updated
  read (the table is compiled once, in `New`, R8, R27).
- **I10** imports only what §1 allows; `depguard` enforces §1's "Must not import" list in CI (`.golangci.yml` rule
  `supervisor-imports`, non-test files: a test may import a backend to run beside the supervisor).
- **I11** every notification gets exactly one `NOTIF_SEND`, or none if `ENOENT` short-circuited it first (R19), if
  the run was cancelled with its relayed syscall still in flight (§4 Timeouts), or if the target abandoned that
  syscall while it was running (E35) — never two.
- **I12** a panicking handler never leaves a notification unanswered when `id` is still valid, and never crashes
  another in-flight notification's worker (R25, E34); recovery is per-notification, not per-`Loop`.

Enforcement: I1–I4, I11–I12 by fuzz/integration tests (§10); I7, I9 by unit tests with `-race`; I8, I10 by `go vet`/
`depguard` in CI; I5, I6 by integration tests asserting response latency is independent of a blocked `Sink`.

**Changes.**
- 2026-09-22, I2 (R30): observe runs continue refusals; no `net:` section continues every connect.
- 2026-09-22, I6: a relayed unix connect takes the task's credentials.
- 2026-09-24, I10: no `depguard` rule held §1's list; `supervisor-imports` added.
- 2026-09-29, I9: the table is compiled once, in `New`; nothing swaps it.

## 9. Conventions and best practices

- **Naming.** Exported: `Loop`, `Options`, `Policy`, `NetRule`, `UnixRule`, `Sink`, `Metrics`. Unexported: `notif`,
  `handlerFunc`, `dispatchTable`, `resp`, `metrics` — each named for the concept it owns (no `util`/`common`).
- **Error wrapping.** Sentinel `var ErrAlreadyRunning`; every wrapped error uses `%w`; no free-text reason ever
  reaches a `record.Event` — only `record.Reason` values (REASON-CHANNEL's closed set), specifics in `rule`.
- **Panic containment.** Every dispatch entry is invoked through a single wrapper that `recover()`s, logs, and
  falls back to R25/R5's safe response before returning control to the worker's `NOTIF_RECV` loop (R25, I12);
  handlers themselves are not expected to guard against their own bugs.
- **Logging.** Own log only (`~/.tego/tego.log`), never agent data; a slow-notification `debug` line carries
  `run=<id> nr=<n> held_us=<n>`, never a path or argv (those belong in the redacted ledger, per OPERATIONS.md).
- **Context.** `Run(ctx)` is the only context-aware entry point — `ioctl`/`process_vm_readv` have no such hook;
  cancellation works only through fd closure (E24), documented on `Run` so callers don't expect faster cancellation.
- **Goroutine ownership.** `Run` starts and joins every worker itself, standbys included; no worker outlives
  `Run`'s return. The one goroutine it does not join is a relay still inside a connect or Fast-Open send on a
  duplicate (§4 Timeouts): it answers and records nothing once `Run` has returned, closes its own duplicate when
  the kernel returns, and is counted against R21's relay ceiling until then. The caller's own `errgroup`
  (P0-DESIGN §2.4) owns `Run` as one of its members.
- **`proto` on a refusal line.** A `net` line's `proto` is `protoOf` the socket's own `SO_TYPE` and `SO_PROTOCOL`, read on the
  duplicate before the answer — refusals of an address this tier cannot decide included, where the socket is read
  for the record alone (R4). Two kinds of line carry `protoOf`'s default instead (`tcp`, or `unix` for a unix
  `dst`), naming no socket: `rule: args-unreadable`, refused before the socket is read (R5), and `rule: fd-raced`,
  `fd-unreadable` or `fd-exhausted`, refused because it could not be read (§7). A consumer that needs the real protocol
  of those has none to get. A `sendfile` or `splice` whose descriptor could not be read is not on a `net` line at all:
  nothing says it is a socket, so it is a `refused` line, op and `target` `fd <n>` (R13's pending frames).
- **Resource lifetimes.** The notify fd is moved into `New`, which closes it when it refuses (amended 2026-10-19,
  ADR 0023 C7; it was the caller's until then); `Run` closes it once, as its shutdown signal. Every `/proc/<pid>/mem` fd is `defer`-closed within its handler; every duplicate is
  closed by its handler or, once relayed, by its relay goroutine (E28).
- **Fuzzing.** Two Go fuzz targets (ARCHITECTURE §7): `FuzzParseSockaddr([]byte)` and `FuzzReadPath` (fake
  `process_vm_readv` fed arbitrary bytes) — assert no panic and output never exceeds the R3 bounds.
- **Benchmarks.** `BenchmarkNotificationRoundTrip` reports p50/p99 held time per syscall kind against the
  P0-DESIGN §9 budget row (a target, not a hard gate in P0).
- **Doc comments.** `doc.go` states purpose, Imports, Must-not-import like every existing package; every exported
  symbol's comment starts with its name.

**Changes.**
- 2026-09-29, `proto` on a refusal line: an `fd-exhausted` line carries `protoOf`'s default, as `fd-raced` does.
- 2026-10-20, `proto` on a refusal line: `fd-unreadable` joins them, and a `sendfile` or
  `splice` whose descriptor could not be read is a `refused` line with no `proto`, not a `net` line claiming `tcp`.

## 10. Tests

**Unit** (no root, fake fd + injected reader): dispatch-table completeness per `GOARCH` (amd64, arm64, table-driven
against R1's `nr` list; a non-amd64/arm64 `GOARCH` fails at compile time, R26); `sockaddr_storage` parsing (valid
`AF_INET`/`AF_INET6`/`AF_UNIX`, truncated buffer, unknown family, oversized `addrlen` — E4); path reader (NUL
within/absent from bound E20, non-UTF-8 bytes E13, exactly the 4097-byte boundary); `argv` reader (exactly 8192
entries, 8193, exactly 128 KiB, 128 KiB+1); the R28 `PATH`-candidate table (a directory before the grant, one after
it, the same basename off `PATH`, another basename on it, an entry declared by path and one declared as a directory,
empty and relative `PATH` elements, a grant that is not on the run's `PATH`) and its statelessness (two threads'
searches interleaved, a search that never reaches a grant, a search abandoned halfway, `record: off`); unix abstract
matching with embedded NULs (E5), pathname resolution against a fake `/proc/<pid>/cwd`, including the notification
going stale across that `readlink` (E9b, R2); resolver TTL refresh (a fresh answer vs. failing-keeps-stale, E29, R27, in
`dns.Set`'s own tests, `-race`); response-shape table (every R18 `(kind,verdict)` → documented
`(continue_,errno,val)`); `Metrics()` under concurrent increments (`-race -count=100`); a synthetic panic injected
into one dispatch entry (I12, R25, E34) confirming the fd stays open, the worker survives, and sibling notifications
on other workers still complete.

**Integration** (`//go:build integration`, root, VM): real `NEW_LISTENER` fd against a purpose-built target —
allowed connect (payload actually flows), refused connect (R10's errno observed), Fast-Open allowed/refused,
connected-UDP decision, unconnected-UDP best-effort (data *does* leave the kernel even when refused, R13b); target
`SIGKILL`ed between trap and read (no panic, no event, worker recovers, E1/R19); target's socket fd closed and
reused for a different socket type between trap and `resolveSocket`'s `getsockopt` (E33); a nested run failing at
startup with `EBUSY` → `launch.ErrChildSeccomp`, exit 125, and none of its notifications reaching the outer `Loop`
(E16/R20); `Workers=1` with N>1 target threads (the
`(N-1)`th's syscall observably blocked, not errored); `ctx` cancel while parked in `NOTIF_RECV` (`Run` returns
within one scheduler tick of the fd close); `argv` over 128 KiB (`argv_truncated: true`, an allowed exec still `CONTINUE`d); relative
opens through a non-`AT_FDCWD` dirfd, including one pointing at an unlinked directory (E8); a run started with an
empty/unreadable `resolv.conf` (E32, R14 falls through cleanly).

**E2E** (`test/e2e`): kill test 5 (`R7`; `test/e2e/kt5-ask.sh`, built 2026-10-05) — an untouched `net`/`fs` ask entry
costs <1% wall time or 1s (whichever is larger) in every tier the machine allows, tier 1 included, measured as the median
wall time of ten runs with the entries over ten without, on the 20-step agent and on `pip install` + `pytest`,
`run_end.supervisor{notifications,held_ms}` present and non-zero in the run that declares them; kill test 1 (two concurrent
runs, no cross-`Loop` leakage, E15, 100% attribution); an `npm install`-class workload against ARCHITECTURE §15's amended
estimate (60–280µs a notification an `fs.ask` entry keeps, end to end: ~0.5–2s for 8k and ~2–8s for 30k), which is open, not
a test: none runs a workload that size (kill test 5's pip build notifies 2,509 times), and R7's allowance closes near ten
thousand kept notifications at 100µs each, so under a contract with an `fs.ask` entry at tiers cgroup and bpflsm such a
workload can miss it until the ask-only filter arm exists (enforce-plane §10.1, open condition 6).

**Fixtures/golden files:** one golden `events.jsonl` slice per dispatch kind (connect-allow, connect-refuse,
fast-open, unix-connect, write-open, exec-truncated-argv, unlink, rename, mkdir, symlink), frozen alongside the M0
fixture ledger (`test/fixtures/ledger/`), replayed through `internal/check` views in CI per `docs/VERSIONING.md` §2.

**Changes.**
- 2026-09-29, TTL refresh: tested in `dns.Set`, since `Loop.UpdatePolicy` is removed.
- 2026-09-30, R22: the fast-path tests scale the ceiling by measured scheduler noise instead of failing a loaded box.
- 2026-09-30, E33: the fd-reuse case names `resolveSocket`'s `getsockopt`, not `handleSendAddr`'s.
- 2026-10-05, E2E (KT5): kill test 5 has its harness, `test/e2e/kt5-ask.sh` with its own self-test and a
  case in the kernel matrix; the bullet said tier 1 only and described a harness that did not exist. Tiers 2 and 3 keep
  every notification while the contract has an `fs.ask` entry (enforce-plane R27), so there the cost is the cost of those
  notifications; each tier's figure is `test/vm/README.md`'s.
- 2026-10-06, E2E: the `npm install`-class item still cited ARCHITECTURE §15's first estimate (30k
  notifications, 0.15–0.25s), which §15 and E17 amended the same day to the measured 60–280µs a notification (~2–8s for
  30k). It cites the amended estimate and says the workload is open: no test runs one that size, and the ask-only filter
  arm that would keep it inside R7's allowance (enforce-plane §10.1, open condition 6) is not built.

## 11. Open questions

- **Connect-refusal errno — resolved 2026-09-23.** R10 used `-EACCES` (SEMANTICS §5, P0-DESIGN §4.2) as a working choice while ARCHITECTURE §7 said `-ECONNREFUSED` and REASON-CHANNEL §1 said `-EPERM`. SEMANTICS §5 ("The errno of a refusal") now owns the answer, `-EACCES` in every tier, with tier 2's kernel `EPERM` only for what this loop relays or continues, and the other three documents say the same. Kill test 6 (b) asks for that errno at tier cgroup and, besides it, for tier 2's own verdicts read from its reason breadcrumb, since the errno there is this loop's.
- **Are the numeric caps in R3, R13b actual P0 rules or implementation defaults awaiting a spec home?** The 8192-entry / 128 KiB argv caps (R3, R16) and the 64-message `sendmmsg` recording cap (R13b; the read itself runs to the kernel's own `UIO_MAXIOV`, which needs no spec home) appear in none of the required normative documents — unlike `Workers` (default 4) and `Budget` (200µs), which P0-DESIGN §2.7 sources explicitly. They carry the same R-numbered presentation as sourced rules only for lack of a better place to record them; `spec/config/v0` has no key for them, nor for `Workers` (see below).
- **Who sets `script`/`stage` on an `exec` record v1 event in tier 1?** Seccomp notifies once per `execve`/`execveat`
  syscall, before the kernel's per-binfmt-stage processing (the `#!` recursion is invisible to seccomp — only
  Landlock's `file_open`/`bprm_check_security` hooks and tier 3's `bprm_check_security` see per-stage calls). This
  package can only supply `path`/`argv`/`exec_id`/`parent_exec_id`; the normative docs do not say which component
  (or whether a best-effort peek at the target file's first two bytes, performed by this package) is responsible for
  `script`, or whether `stage` is populated at all in tier 1.
- **Nested-run policy composition mechanism at a shared listener (R20/E16).** SEMANTICS §3 requires composed
  (intersected/unioned) policy per nested run, and ARCHITECTURE §3 says a nested run's notifications are "routed
  through the parent's supervisor," but no document specifies how the parent's single `Policy` learns a nested run's
  narrower composed table. *Updated 2026-09-22:* this spec used to assume P0 applies the ancestor's own policy to the
  nested run's notifications. P0 does not route them at all: the nested child's `NEW_LISTENER` fails `EBUSY` and the
  launcher fails the start (R20, E16), which is the fail-closed answer and is what R20 now says. Three documents
  still disagree with that: ARCHITECTURE §3 describes the routing as if it were built, runtime-launch.md's case 6
  calls this `EBUSY` a programming error reachable only by misuse, and P0-DESIGN §2.6 cites R20 for the observe
  case alone. The routing becomes buildable once a nested run can hand its
  composed table to the ancestor's loop keyed by its cgroup, and the ancestor's loop decides per notification by
  that key.
- **Non-UTF-8 byte preservation in the ledger (E13).** Neither `spec/record/v1/README.md` nor `pkg/spec/record`'s
  `MarshalLine` contract states how a non-UTF-8 path or argv byte sequence should be encoded; today's behavior
  (lossy `encoding/json` substitution) may need a schema decision (e.g. a documented escape convention) that is this
  component's problem to surface but not this component's to decide alone.
- **`Policy.TTL` source and default.** SEMANTICS §5 says hosts "re-resolve on TTL" without naming where the TTL
  number comes from (the resolved DNS answer's own TTL vs. a fixed interval) or a default value; `spec/config/v0`
  has no `supervisor.*` or `net.ttl` key.
- **Is `Options.Workers` operator-tunable?** P0-DESIGN §2.7 states "default 4" but `spec/config/v0/README.md`'s
  machine config has no key for it (unlike `record.ringbuf` for `observe`'s ring buffer); unclear whether it should
  gain one or stay a compiled-in constant for P0.
- **Truncation signaling for `fs` events.** R16 adds `argv_truncated` to `exec`, but record v1's `fs` payload
  (`op path path2 flags count`) has no equivalent field for a path that hit the 4097-byte scan bound (E20); whether
  P0 needs one, or an empty/malformed `path` is an acceptable signal on its own, is unresolved.

## Resolved conflicts
Resolved (2026-09-22): `internal/runtime/supervisor` is now in the layout with its own `doc.go`; `internal/runtime/ask` builds on it in P1; FEATURES E13 is split into E13a (P0: loop, connect decisions, record) and E13 (P1: approvals); the 200 µs figure is the soft anomaly ceiling and under 10 µs the typical fast path (P0-DESIGN §2.7).

## Corrections from the implementation (2026-09-22)

Measured on the test machine (Linux 6.17, uid 1000, Landlock ABI 7) while building `internal/runtime/supervisor`.
Each item replaces the spec text it names; nothing else in this document changed.

- **E24 is wrong: closing the notify fd does not unblock a pending `NOTIF_RECV`.** The ioctl sleeps in
  `down_interruptible()` on the listener's request semaphore, which a `close(2)` does not post. Measured: a
  worker blocked in `SECCOMP_IOCTL_NOTIF_RECV` was still blocked two seconds after another thread closed
  the fd (`internal/runtime/supervisor/integration_test.go`, `TestIntegrationListenerHangup` documents it). `EINTR` is no help either — `RECV` restarts on
  it, as `platform/sys` must, so a signal cannot be the stop either.
  **What the implementation does instead:** each worker `poll(2)`s the listener together with an internal
  self-pipe and calls `RECV` only once `POLLIN` says a notification is pending, holding a mutex across
  poll+recv so exactly one worker is ever inside the ioctl. Cancellation writes one byte to the self-pipe
  (plus a 200 ms poll slice as a backstop), workers return, and `Run` closes the fd **after** the last
  worker has left the ioctl rather than underneath it. `POLLHUP` on the listener — the last task carrying
  the filter has exited — ends `Run` with `nil`; `POLLERR` alone (a signal interrupted the poll's lock on
  `notify_lock`) is polled again (amended 2026-10-16). The kernel's own `-ENOENT` from `RECV` covers the race
  where a pending notification is withdrawn between the poll and the receive (R19).
- **R10's errno is `-EACCES`**: `refusalErrno` in `dispatch.go` is the single place it is written. `EACCES`
  also matches what Landlock's own net backstop returns, so a refusal looks the same however it was reached.
  (ARCHITECTURE §7's `-ECONNREFUSED` and REASON-CHANNEL §1's `-EPERM`, unreconciled when this was written,
  were corrected to `-EACCES` on 2026-09-23; §11.)
- **`New` returns an error.** §4's signature has no error return, but `New` validates the fd, the policy
  (a nil rule table, a nil resolver, an empty run id, a malformed agent id) and the sink; a run must not
  discover a policy it cannot decide from on its first notification. `UpdatePolicy` validates the same way.
- **`Policy` is the shape §2 describes, reached differently.** The compiled TCP/UDP tables with their live
  IP sets live in `internal/platform/dns.Set`, which the policy holds as a `Resolver`: it owns R8/R8a's
  merge-then-swap and R27's ownership statement, and `Loop` reads it lock-free per notification. `Policy`
  itself carries the `*agent.RuleTable` (unix entries, fs entries for advisory verdicts, exec entries),
  the run and agent ids, the record mode and the argv budget.
- **Socket type costs a duplicate.** §4's `resolveSocket` (for `sendDecisionCtl`) needs `SO_TYPE` to tell a Fast-Open send from a
  datagram one, and the same is true of a `connect` whose event must say `tcp`, `udp` or `raw`: the type
  is read from the `pidfd_getfd` duplicate the decision needs anyway, so a network notification takes one
  `pidfd_open` + `pidfd_getfd` + `getsockopt` and closes both descriptors inside the handler (E28, E33).
  A `sendmsg` with `msg_name == NULL` is answered `CONTINUE` before any of that happens — save under the
  `models[]` guard, and with `MSG_FASTOPEN` under a `net:` section, where it takes the duplicate too
  (`sendUnaddressed`, R12, R13b).
- **`exec_id` needs the thread group.** `notif.pid` is the trapping thread's tid; `/proc/<tid>/stat` carries
  that thread's own start time, not the process's. The exec handler resolves `Tgid` from
  `/proc/<tid>/status` once per exec and builds `<run>/<tgid>/<start-boot-ns>` from `/proc/<tgid>/stat`.
  Other events carry the tid in both `pid` and `tid` rather than pay that read per notification.
- **`errgroup` is not used** (§9 names it): `golang.org/x/sync` is not a module dependency of this repo and
  this repo takes no dependency the spec does not name. `Run` starts and joins its workers with
  `sync.WaitGroup` and keeps the first worker error under a `sync.Once`; the ownership guarantee §9 asks
  for (no goroutine outlives `Run`) is unchanged.
- **Measured fast path.** `TestIntegrationFastPath`: 9.2 µs per notified `mkdirat` round trip (2000
  operations, real listener, four workers) against P0-DESIGN §9's under-10 µs budget and R22's 200 µs
  ceiling. The package's own share of that, with the kernel faked, is 1.1 µs
  (`BenchmarkNotificationRoundTrip/mkdir_continue`), so the remainder is the ioctl and `process_vm_readv`
  round trips: six syscalls per record-and-continue notification (poll, recv, two `ID_VALID`, one
  `process_vm_readv`, one send).
- **Two additive record v1 fields, not one.** §2 adds `argv_truncated` to the `exec` payload. The `net`
  payload needs the same treatment for R13b: a refused datagram send is recorded as refused but the data
  left the kernel anyway, and without a marker that line is indistinguishable from a refusal that actually
  stopped something. Unconnected `sendto`/`sendmsg`/`sendmmsg` events therefore carry `best_effort: true`.
  Connects, Fast-Open sends and unix connects never do under a `net:` section: those are enforced. Under a
  contract with no `net:` section they are continued like the sends, and carry it too (R7) — except on an IP socket
  under the `models[]` guard, where they are decided and relayed and carry none.
- **Read-opens need the other half of SEMANTICS §2.** R15 gives the advisory verdict as "allow if the path
  falls under a `write` entry, else refused", which is right for a write-open and wrong for the read-opens
  `record: full` notifies (enforce-landlock R16): a read outside every entry is *allowed* — "unmatched
  (reads allowed, everything else refused)". The implementation splits on the open's own flags: a read-open
  is refused only when the nearest entry is a `deny_read`, with reason `read-denied`; everything that
  modifies keeps R15's rule and its own reason code.
- **A failed `SO_TYPE` fails closed.** E33 describes the fd number being reused between the trap and the
  duplicate, and prefers the degrade direction when the type is *misread*. When the `getsockopt` itself
  fails, the duplicate is not a socket at all and there is nothing to decide against: that is the same
  class as a failed `pidfd_getfd` and takes the same answer (refused, `rule: fd-raced`).
- **A declared port of 0 is not a wildcard.** R7's "(or is 0, ICMP/raw)" reads as a port wildcard, and
  implementing it that way turns `net.allow: ["10.0.0.5:0"]` — written to permit ping — into permission
  for every TCP and UDP port on that host. SEMANTICS §5 is the narrower statement and the one that holds:
  "ICMP and raw datagram sockets match by host with port 0". A port-0 entry therefore matches a
  destination whose port is also 0, and a raw socket whatever port its address carries; it never admits a
  tcp or udp destination on a real port.
- **An `fs.watch` entry carries no rights and must not shadow a grant.** `agent.FSRule` gives watch, like
  deny_read and the implicit entries, `Access: 0`, and SEMANTICS §7 makes it a recording selector. Taking
  it as the nearest entry under `write: [/work]`, `watch: [/work/logs]` would record every write under
  `/work/logs` as refused while Landlock — allow-only, unioned within a layer — actually permits it, and
  would also hide the "unix socket under a declared write directory" allow of SEMANTICS §5. Watch entries
  are left out of the nearest-wins table entirely.
- **`record: off` does not suppress a refusal.** REASON-CHANNEL §1's second guarantee is "the reason
  record, always", and this package is the only producer of the write/delete/rename/mkdir-outside-contract
  codes. `record: off` therefore drops the advisory record of an allowed operation and of an operation
  whose path could not be read — nothing was decided there — but never a refusal.
- **An abstract unix name is the addrlen-bounded bytes, with nothing trimmed.** E5 says "never
  NUL-scanned", and the kernel agrees in both directions: `@bus` and `@bus\0\0` are two different
  sockets. Stripping the zero padding a `memset`-then-`sizeof` caller leaves behind would match a declared
  `unix:@bus` against a connect to a different socket. An abstract name of no bytes at all is an unnamed
  socket, and a unix address with neither a path nor a name is refused rather than resolved against the
  target's cwd (where it would pick up an `fs.write` grant).
- **A send on a connected stream socket is continued, not decided.** The kernel ignores `msg_name` once
  the socket has a peer, so the bytes go where the connect decision already sent them (R13a). The handler
  checks `getpeername` on the duplicate before treating an addressed send as Fast Open; without that, a
  stale `msg_name` on a connected socket could refuse a send the kernel was going to deliver anyway.
  (Narrowed by the second pass below: not for a send carrying `MSG_FASTOPEN`, and not for
  an address this tier cannot decide.)
- **Ancillary data on a relayed send is refused, never dropped.** R12's relay sends the gathered payload;
  it cannot reproduce an `SCM_RIGHTS` array, whose descriptor numbers name the *target's* table and would
  hand out this process's own descriptors if passed on. An unconnected stream socket cannot legally pass
  descriptors anyway, so such a send is refused with `rule: ancillary-data` rather than delivered without
  its ancillary data under a success return (I3).
- **Open question answered for P0: `Policy.TTL`.** The TTL comes from the compiled `agent.NetRule.TTL`
  (`agent.DefaultDNSTTL`), floored by `dns.DefaultMinTTL` (30 s), and the refresher wakes every
  `dns.DefaultInterval` (15 s). No `spec/config/v0` key was added.

## Corrections from the P0 audit (2026-09-22)

Four defects found by audit of the implementation against this document. Each item replaces or extends the
spec text it names; the rule bodies above already carry the change.

- **`sendmmsg` was a fail-open hole in R12 (security).** R13b lumps `sendmmsg` with the datagram
  best-effort rule and `handleSendMMsg` implemented it literally: it read every `msg_name`, decided each
  destination, and then answered `CONTINUE` whatever the socket type and whatever the verdict. On an
  unconnected `SOCK_STREAM` fd with `MSG_FASTOPEN` that is `tcp_sendmsg_fastopen` opening the connection
  and the payload leaving for an undeclared host, while the ledger recorded
  `net verdict=refused best_effort=true` for the destination the bytes actually reached — a refusal line
  for data that was exfiltrated, which `drift` and `measure` then counted as a refusal. The code's own
  justification named Landlock's per-port rule as the backstop; enforce-landlock R6 says that rule "is
  port-only and cannot see the host", which is why the supervisor is the authoritative decider in the
  first place (I2). An agent blocked on `sendmsg` only had to call `sendmmsg` with `vlen=1` and the same
  `msghdr`. **R13c** now states the rule and the dispatch row is a decision kind, so the R25 panic path
  and `finish`'s safety net refuse it rather than continuing it.
- **The relayed `connect()` must not be the thing `Run` is joined on.** §4's "no handler sets a deadline
  on any `connect()`" is a deliberate decision and stands; performing that syscall *inline on a pool
  worker* was not, and was a liveness failure rather than a latency one. Cancellation reaches a worker
  only inside `receive()` — the wake byte and the 200 ms poll slice both — so one allowed connect to a
  blackholed host pinned `Run`'s `workers.Wait()`, and the runner's `group.Wait()` behind it, for the
  kernel's whole SYN retry schedule (~127 s at `tcp_syn_retries=6`): `run_end` unappended, the run
  directory's flock still held, `tego status` still reporting the run live, minutes after the wall budget
  had already SIGKILLed the agent. With `DefaultWorkers=4` four such connects park the entire pool and
  every notified syscall of every thread stays trapped. The relay now runs on its own goroutine, which
  owns the duplicate; the handler selects on it against the run's cancellation (§4 Timeouts, I11). The
  residual, unchanged, is R21/E17's documented backpressure: while a relay is outstanding its worker is
  still busy, so a genuinely slow connect still costs one of `Workers` slots until it completes or the run
  is cancelled. Cost of the handoff, measured with the kernel faked
  (`BenchmarkNotificationRoundTrip/connect_allow`, 300k iterations): 1.49 µs → 2.28 µs per allowed
  connect. It touches only the two relayed paths, not the record-and-continue path a build-like workload
  is made of (0.94 µs, unchanged), and is two orders of magnitude inside R22's 200 µs ceiling.
- **R2 admits no exception, `execveat(AT_EMPTY_PATH)` included.** That branch reached
  `readlink("/proc/<pid>/fd/<dirfd>")` with no `ID_VALID` before it and none after — the only liveness
  test in it was an `if n.gone` that nothing in the branch had set — so a dead notification still had its
  `/proc` read and still produced an `exec` event, naming whatever binary the pid's reuser held on that
  descriptor number (E3). `recordSymlink` had the pre-check and not the post-check on the link target.
  Both are bracketed on both sides now, like every other path read.
- **`AF_UNSPEC` is not an unrecognized family.** R4/E4's blanket rule refused `connect(fd, {AF_UNSPEC},
  len)` with `-EACCES` and wrote `net verdict=refused reason=net-not-allowed dst=family(0)` for a call
  that named no destination. See R4's carve-out — `connect(2)` only, as the corrections below
  record: it is relayed, not `CONTINUE`d — `CONTINUE` would hand
  the kernel a sockaddr a sibling thread can rewrite between the decision and the kernel's own read, which
  would turn a carve-out for a harmless call into an undecided connect to anywhere.

## Corrections from the relay audit (2026-09-22)

Three findings from reviewing this package against what the same kernel mechanisms have done to other
people (`seccomp_unotify(2)`, LXD's syscall supervisor, runc #4328, the cgroup-BPF attachment semantics
Cilium documents). Each replaces or extends the spec text it names; the rule bodies above already carry
the change.

- **A parked relay must not cost the pool a worker (R21).** R21's "the `(Workers+1)`th notifying thread
  blocks inside its own trapped syscall until one frees up" and E17's 4–8 µs per notification describe a
  pool of microsecond handlers. (E17's figure was an estimate and is amended, 2026-10-06: measured end to end it is
  60–280 µs. The contrast below is with a connect's ~127 s and holds at either.)
  R9's connect-on-duplicate is a handler that can legitimately run for the
  kernel's whole SYN retry schedule, and only a worker inside `receive()` ever calls `NOTIF_RECV`, so at
  `DefaultWorkers=4` four allowed connects to one declared host that a firewall has started dropping stop
  the run being supervised at all: every `openat`, `execve`, `mkdir`, `unlink` and `rename` of every
  thread stays trapped in the kernel, the agent looks hung, and `tego status` reports a healthy run
  throughout. This needs no attacker — an allowed host whose route blackholes, dialled by four threads of
  one connection pool, is enough. The worker about to park now hands its place to a standby and retires
  when its handler returns; `maxStandby` (64) bounds the standby workers, and with them the relays a
  handler is still parked on, whose real cost is one goroutine and one duplicate descriptor each, and
  `metrics.starved` counts the times that ceiling was reached. (It does not bound a relay whose handler
  has returned; see the corrections below.) Cost, measured with the kernel faked
  (`BenchmarkNotificationRoundTrip`, 200k iterations): allowed connect 2.28 µs → 3.02 µs, from the timer
  the two watches share; the record-and-continue path a build-like workload is made of is unchanged at
  0.98 µs, and both are two orders of magnitude inside R22's 200 µs ceiling.

- **A cancelled notification is not a dead target (E2 vs the new E35).** E2 and E31 both frame a stale id
  as the target having *died*. `seccomp_unotify(2)` describes a second, commoner cause with the opposite
  consequence: a signal delivered to a target blocked in a notified syscall cancels the notification and
  **the kernel restarts the syscall**, raising a fresh notification — "even for the blocking system calls
  listed in signal(7) that would never normally be restarted by the `SA_RESTART` flag". Since R9 and R12
  perform the syscall before answering, the side effect is already done when `NOTIF_SEND` returns
  `ENOENT`, and the restart performs it again: duplicate application bytes for a relayed send, a spurious
  `EISCONN` for a restarted connect, two `allow` lines in an append-only chain for one call. `respond`
  swallowed that `ENOENT` as ordinary (`isGone`), so it was invisible even in the log. The loop now does
  what the same man page tells a supervisor emulating a blocking syscall to do — poll
  `SECCOMP_IOCTL_NOTIF_ID_VALID` while the relay is outstanding — and on a stale answer stops waiting,
  counts `metrics.orphaned`, logs at `warn`, and records the launched syscall with `result_unknown: true`
  rather than dropping it. **Three additive record v1 fields now, not two:** `argv_truncated`,
  `best_effort` and `result_unknown`, each `omitempty`, each within VERSIONING §2.

  *What this does not fix, and what would.* The double side effect itself cannot be prevented from this
  package: the window is between the last `ID_VALID` and `NOTIF_SEND`, and it contains the syscall.
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (`1UL << 5`, Linux 5.19, — added precisely for
  supervisors doing non-reversible work) closes it: once userspace has received the notification, the
  target ignores non-fatal signals until a response arrives, so the residual window moves to *before* the
  `RECV`, where no side effect has happened and a restart is harmless. *Done since (policy semantics, below):*
  `internal/platform/sys.SeccompSetFilterNewListener` now asks for `NEW_LISTENER|WAIT_KILLABLE_RECV` and
  retries with `NEW_LISTENER` alone on `EINVAL`, so a 5.14 kernel (RHEL 9, ARCHITECTURE §14) still starts; the
  flag's own 2025 race fix (`cce436aa`, "seccomp: Fix a race with WAIT_KILLABLE_RECV if the
  tracer replies too fast") is noted there. Still open, outside this package: a `doctor` probe beside D5 that
  tests the flag rather than trusting a version number, and the kernel-minimums table note.

  *Unverified.* The `ID_VALID` watch is unit-tested against the kernel seam, and the kernel behaviour it
  rests on is quoted from `seccomp_unotify(2)` on the test machine, but the end-to-end path — a real `SA_RESTART`
  signal delivered to a real target inside the relay window — has no integration test. It would need a
  new child mode in the integration harness plus a destination that parks a real `connect(2)` on demand,
  and the timing makes it inherently flaky; recorded here rather than faked.

- **R9 vs `enforce-cgroup-observe.md` R5: tier 2's network verdict, judged and not changed here.** This
  package relays an allowed connect from the supervisor process on a `pidfd_getfd` duplicate (R9) and
  never answers `CONTINUE` (I2). At tier 2 that composition has a consequence neither document states.
  The kernel picks which cgroup's program array to run from the *socket*
  (`cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data)` in `__cgroup_bpf_run_filter_sock_addr`, fixed at socket
  creation), so the run's `connect4`/`connect6` program does run — but `bpf/cgroup_net.bpf.c` keys its own
  policy lookup on `bpf_get_current_cgroup_id()`, which is the *calling task's* cgroup, and that is the
  supervisor's. The lookup misses, the program takes its neutral branch, no breadcrumb is written, and
  the in-kernel network verdict never happens; `enforce-cgroup-observe.md` §5 R5's "the tier-2 seccomp
  handler answers `CONTINUE` and reads `reason_val`" has nothing to read. (Verified against
  `kernel/bpf/cgroup.c` v6.12 — `cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data)` — and
  `bpf/cgroup_net.bpf.c:104`.) To be clear about the blast radius: connects are **not** unenforced at
  tier 2. This package decides and then relays or refuses every one of them in userspace exactly as it
  does at tier 1, because `enforce/cgroup` installs the identical tier-1 filter. What is inert is the
  in-kernel backstop and the breadcrumb R5's `net` ledger event was meant to be read from.

  Nothing about this is fixed by changing this package, and the obvious change would make things worse:
  answering `CONTINUE` for a connect hands the kernel back a `sockaddr` that a sibling thread of the same
  process can rewrite between this loop's decision and the kernel's own read — the exact reason R4's
  `AF_UNSPEC` carve-out is *relayed* rather than continued — and it contradicts I2 and R9. The fix belongs
  where the identity is chosen: the BPF program should derive it from the socket the kernel already
  selected the program array by, not from `current`. **Which helper serves that for
  `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` is unverified here**: `bpf_sk_cgroup_id` is documented for
  `cgroup_skb`, and that file's own header comment shows the helper set differs per program type, so it
  needs checking against `sock_addr_func_proto()` the way it already checked
  `bpf_get_current_cgroup_id`. Until then,
  `enforce-cgroup-observe.md` R5 and this document's R9/I2 are a genuine cross-document conflict, and I4
  ("the ledger's net verdict for a `connect4/6`-decided connect always matches the real syscall result")
  is untestable at tier 2 because no `connect4/6` decision is reached. `TestConnectIsNeverContinuedWhateverItDecides`
  pins I2 across every outcome `handleConnect` has, so flipping this package to `CONTINUE` for a tier has
  to be a decision someone makes deliberately.

## Corrections: `AF_UNSPEC`, relays and fail-closed choices (2026-09-22)

Four more defects. The rule bodies above carry each change;
this records why, and where the spec text moved to meet a fail-closed choice.

- **R4's `AF_UNSPEC` carve-out is `connect(2)`'s alone, and a send refuses it (R4, E4, R13b, R18).** The
  carve-out had been implemented in the shared decision, so `sendto`/`sendmsg`/`sendmmsg` with an
  `AF_UNSPEC` address were recorded `observed / net.unspec / dst=unspec` while `udp_sendmsg` and
  `raw_sendmsg` delivered to the `sockaddr_in` behind the family word. The first fix recorded them
  `refused / unmatched` but still answered a datagram `CONTINUE` under R13b: the datagram still left, its
  line still did not say where to, a declared host behind the family word was recorded refused while the
  kernel delivered to it, and the same bytes in family 17 were answered `-EACCES`. Reading the embedded
  address instead was considered and rejected: what those bytes name depends on the socket's domain
  (`sockaddr_in` for IPv4 UDP and raw, `sockaddr_in6` for raw IPv6, "no address, use the peer" for IPv6
  UDP), which this tier never reads. So outside `connect(2)` `AF_UNSPEC` is an unrecognized family, and an
  unrecognized family on a send is refused with R10's errno. **Spec amended to match:** R13b's "always
  `CONTINUE`, regardless of verdict" now says it covers only a destination this tier could match. `sendto`
  and `sendmsg` already refused every unrecognized family before the socket was read. `sendmmsg` on a
  datagram socket was the exception, and it was the `vlen=1` route around that refusal, so a batch
  carrying an undecidable address is now refused whole, with `batch-send` on any declared destination
  beside it. The deliberate cost: `sendto(fd, …, {AF_UNSPEC}, …)` on a connected IPv6 UDP socket, which
  the kernel would send to the peer, is refused. The portable spelling of that send is a NULL address.
  (Pass 2 below: the batch refusal read only the first 64 messages, the refusal recorded `proto=tcp`
  because the socket was not read, and connected TCP was a second, unlisted cost.)
- **Relay goroutines are counted and capped (R21, E28, R29, §7, §9).** `maxStandby` bounded the standby
  workers, but an orphaned relay (E35) gives its standby slot back while its goroutine keeps the
  duplicate until the kernel's connect returns, and the kernel's restart of the abandoned syscall starts
  another. 192 orphaned relays held 192 duplicates against `maxStandby=64` with `standby` and `starved`
  both zero, while `closeDup`'s comment claimed the pool and `maxStandby` bounded them. The relay
  goroutines are now capped at `Workers + maxStandby`. Past that cap an allowed connect or Fast-Open send
  is refused with R10's errno and `rule: relay-limit` (a new §9 sentinel), counted in
  `metrics.relayLimited`. §9's "none outlives `Run`'s return" was already false for relays and now says so.
- **`PIDFD_THREAD`'s fallback is described where it happens (R11 note).** `sys.PidfdOpenThread` itself
  retries the plain `pidfd_open`, so below 6.9 the call does not simply fail. It succeeds for a
  thread-group leader and refuses any other tid, and that refusal (whatever its errno) is what
  `duplicate`'s tgid fallback serves.
- **R28's candidate table asks `ExecRule.ByName`, not `Raw`.** The compiler collapses spellings that
  resolve to one file into one rule and keeps the first spelling in `Raw`. So `command: [/usr/bin/python3]`
  beside `exec.allow: [python3]` has a path for `Raw`, and the run's own `execvp` probes were recorded
  `refused / exec-not-allowed` (drift) instead of `observed / path_search`. `ByName` records that some
  spelling was a bare basename, which is the question R28 asks.

## Corrections: the `sendmmsg` batch (2026-09-22)

The rework above had three problems, and working them found a fourth.
The rule bodies above carry each change; this records why.

- **The `sendmmsg` batch refusal reads as far as the kernel sends (R13b, R13c, E4, R18).** The refusal of a
  batch holding an undecidable address ran over the messages the handler had read, and it read 64. The kernel
  clamps `vlen` to `UIO_MAXIOV` (1024) instead and sends every message up to that, so `vlen=65` with an
  `AF_UNSPEC` message at index 64 was answered `CONTINUE`, 64 lines and none for the 65th, which `udp_sendmsg`
  delivered to the `sockaddr_in` behind its family word; with the first 64 messages carrying no address the
  handler never even took the socket. The route round `sendmsg`'s refusal had only moved from `vlen=1` to
  `vlen=65`, and four statements (the `send.go` comment, R13b, E4, R18) claimed more than the code checked.
  The headers are now read to `min(vlen, 1024)` in one bracketed read, and every addressed message's address
  with them; the first 64 are recorded as before, and an undecidable message past them refuses the batch and is
  recorded too. A header the read does not reach fails closed (R5). Refusing any datagram batch longer than 64
  outright was the cheaper alternative and was rejected: it breaks a legitimate long batch to spare about 1.1 µs
  per message. The unrecorded tail of an all-decidable batch is listed in R13b as a residual. Verified on a real
  listener: `vlen=65`, 64 `AF_INET` datagrams and one `AF_UNSPEC` to a loopback receiver, is now `EACCES` with
  nothing delivered; with the read reverted to 64 the call succeeded.
- **`tcp_sendmsg_fastopen` refuses `AF_UNSPEC` itself (R4).** The rework said TCP's Fast-Open path hands an
  `AF_UNSPEC` address to `__inet_stream_connect`. On this 6.17 kernel it answers `EOPNOTSUPP` before any connect
  (`sendto(MSG_FASTOPEN)` on an unconnected `AF_INET` TCP socket; the same bytes with `sa_family = AF_INET`
  connect and send). R4 and the test comment now say so; the refusal it argued for is unchanged.
- **A refusal of an undecidable address names the socket's protocol (R4, E4, §9).** `sendto`/`sendmsg` (and
  `connect(2)` with an unrecognized family) refused before the socket was read and wrote `proto=tcp`, including
  for the UDP and raw sends that are the only ones the kernel would have delivered; `sendmmsg`, which does read
  the socket, wrote `udp` for the same `msghdr`. The socket is now read for the record before the answer, which
  does not depend on it; a socket that cannot be read makes the line `fd-raced`. §9 now states which lines carry
  `protoOf`'s default (`args-unreadable`, `fd-raced`). **Spec amended to match a fail-closed choice:** R4 lists
  the second deliberate cost the rework left out — an `AF_UNSPEC` or other unrecognized address on a connected
  TCP socket, which the kernel ignores, is refused — and `sendmmsg` on a connected stream socket, which the
  rework still `CONTINUE`d undecided, now refuses such a batch too, so the same `msghdr` gets the same answer
  from `sendmsg` and from `sendmmsg` with `vlen=1`, and R18's "any send whose address this tier cannot match"
  is true without an exception.
- **`MSG_FASTOPEN` on a connected stream socket is decided, not continued (R12, R13a, R13c).** Found while
  working the above. The connected-stream shortcut answered `CONTINUE` on the strength of `getpeername` on the
  duplicate. A sibling thread's `connect(fd, {AF_UNSPEC})`, which R4 allows, can dissolve the association
  between that check and the kernel running the send, and `tcp_sendmsg_fastopen` then connects the peerless
  socket to the send's own address — measured on 6.17: connect, `connect(AF_UNSPEC)`, `sendto(MSG_FASTOPEN)` to
  a second listener delivers there. With `MSG_FASTOPEN` the send is now decided as R12 whatever the socket's
  peer (`sendmmsg`: refused, R13c). Nothing legitimate is lost: while the peer stays, the kernel answers such a
  send `EISCONN`, which an allowed relay returns as the real result (checked on a real listener).

## Corrections: `sendmmsg` past the 64th message (2026-09-22)

The `sendmmsg` change above had two problems. The rule bodies above carry
each change; this records why.

- **A datagram past the 64th message reached an undeclared host with no line (R13b, R13c, security).** That change
  read every address up to the kernel's clamp but, past the 64th message, only asked whether each one was
  decidable: none was matched against the policy and none recorded, and a batch whose first 64 messages carried
  no address never took the socket at all. On a connected UDP socket the kernel sends the unaddressed messages to
  the peer and each addressed one to its own `msg_name` (measured on 6.17: 64 `NULL`-name messages and one
  addressed to a second receiver returned 65, the peer got 64 and the second receiver 1), so that batch was
  `CONTINUE`d with no line, and 64 declared messages followed by 960 to an undeclared host wrote 64 `allow` lines
  while the undeclared host received 960 datagrams. At this tier UDP is record-only, so the ledger is the only
  control, and this emptied it. The reason that change gave for the residual, bounding the ledger, did not hold: the
  addresses were already read, and one more line keeps the bound at 65. The messages past the 64th are now
  decided with the socket's `proto` once the socket is read, and the first destination there that the policy does
  not admit is recorded `refused` / `unmatched` with `best_effort`, the batch still `CONTINUE`d as R13b says. A
  batch whose only addresses lie past the 64th takes the socket like any other; only a batch with no address in
  any message the kernel sends keeps the no-line `CONTINUE`. **Spec amended to match a fail-closed choice:** on a
  stream socket without a peer, or under `MSG_FASTOPEN`, such a batch was `CONTINUE`d undecided; it is now R13c's
  refusal like one with the address first, and a failed `pidfd_getfd` or `SO_TYPE` refuses it as `fd-raced`. The
  residual R13b now lists is narrower but not empty: past the 64th, admitted destinations are not recorded, and
  neither is any unadmitted one after the first, so the line shows that the batch reached a host the policy does
  not admit, not every such host. Recording every distinct unadmitted destination there would have closed that
  too, at up to 1024 lines per call; it was not done, so that one call still writes at most the 65 lines R13b's
  recording cap sets. Verified on a
  real listener: the connected-UDP batch above now writes one best-effort refused line naming the second receiver,
  and with the handler reverted it wrote none.
- **R13b said more than the handler read (R13b).** It said the handler read the address of every addressed
  message up to the clamp and that the tail was "read and checked". The read stops at the first undecidable
  address past the 64th, which refuses the batch, and "checked" was a decidability test, not a policy match. R13b
  now says where the read stops and what is decided past the 64th, and the residual names what stays unrecorded.

## Corrections: policy semantics (2026-09-22)

The rule bodies above carry each change; this records why.

- **No `net:` and no `exec:` refused what SEMANTICS §1 says they allow (R7, R16).** The Landlock builder and
  `agent.Evaluate` read "no `net:`" as unrestricted, but this loop matched every connect against a resolver set
  with no rules and refused all but DNS and the forwarder's loopback, and refused every unix socket not under a
  write directory; with no `exec:` it recorded every exec other than the command's and the MCP servers' as a
  refusal, which the pipeline mirrored into a `refused` line and `last-refusal.json`. Three components answered
  one contract three ways. The loop now reads both bits off the contract as the builder does. The exec open is
  still a read, so an undeclared binary under a `deny_read` tier 1 enforces is recorded `read-denied`, exactly
  as `Evaluate`'s Landlock arm answers it. *Then:* the first fix relayed every connect under no `net:`,
  which performed it from this process and so outside the agent's Landlock domain and, at tier 2, as root; each
  one is now `CONTINUE`d and recorded `best_effort` (R7, I2, I6). Tier 2 had also refused every TCP and UDP
  destination of such a contract in its own programs; it now attaches none for one
  (`internal/runtime/enforce/cgroup`, `RuleMaps.Unrestricted`), and a TCP and a UDP connect of a contract with no
  `net:` both succeeded there as root in the KVM guest, so `Evaluate`'s `allow` holds in every tier.
- **A relative unix `sun_path` was relayed to the launcher's directory (R11, security).** Found while working
  the above. The destination was decided against `/proc/<pid>/cwd`, but the relay passed the target's own
  relative bytes to `connect(2)` in this process, which resolves them against its own cwd: an agent that
  changed directory could have a connect decided for one socket and performed on another. The relay now names
  the decided absolute path, and refuses one too long for `sun_path`. *Then:* with the cwd unreadable
  R6 leaves the path relative, and the no-`net:` admit relayed those bytes after all; nothing under no `net:` is
  relayed now, and `relayAddr` refuses a relative decided path whatever admitted it (`rule: path-unreliable`).
- **R13b's refusal rested on where the read stopped (R13b).** Pass 3 decided the batch's refusal from the tail's
  last entry and the tail line's undecidable case likewise, which was right only because `mmsgDests` stops at
  the first undecidable address. Both now ask every entry read. Two rows pin it: an `AF_UNSPEC` at 64 followed
  by a declared message at 65, and a declared message at 64 followed by `AF_UNSPEC` at 65.
- **A `msg_name` with a zero length refused the send (R13c).** `__copy_msghdr` treats it as no address; this
  loop read it as an unreadable address and refused, at any index up to the kernel's clamp. `sendmsg` had the
  same fault. Both now take the kernel's test.
- **R13b's cost sentence generalised one measurement.** Both measured batches repeated one address, so the tail
  was decided once. The sentence now says so and gives the worst case, measured.
- **GAPS A9 had no producer (R31).** `landlock-topology` was in the reason set and nothing emitted it.
- **P0 wrote no `mcp` event (R16).** The exec of a declared server is now recorded as its start.
- **`WAIT_KILLABLE_RECV` and `SYNC_WAKE_UP` (E35).** The first is set where the listener is born (above). The
  second, `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP` (6.6), was wrapped in `internal/platform/sys` with no caller;
  `New` now asks for it on the listener, best effort — it changes scheduling only. *Then:* the first
  flag was presented as a pure win; it holds the target's non-fatal signals for a relay's whole, undeadlined
  duration, which E35 and §4 now state, and the comments that said the kernel restarts an orphaned syscall now
  say that holds below 5.19 only.

## Corrections: supervisor policy (2026-09-22)

The rule bodies above carry each change; this records why, and where a fail-closed choice moved the spec.

- **A relayed unix connect reached any socket through a symlink, and at tier 2 as root (R11, I6, security).**
  `decideUnix` admitted a socket under a write entry by its cleaned path string, and the relay then passed the
  target's bytes to `connect(2)` in this process, where the kernel followed every symlink in them. A symlink the
  agent made in its own write directory therefore admitted every pathname socket on the machine, recorded `allow`
  against the write entry: on 6.17 unprivileged a direct connect to an undeclared socket outside the write
  directory got `EACCES`, and the same connect through `ln -s` inside it was relayed and accepted. And every relay
  ran with this process's credentials, which at tier 2 are root's: a uid-1000 task reached a `0600` socket in a
  `0700` root directory, and the listener read uid 0 in `SO_PEERCRED` (the root case verified in the KVM guest).
  The shipped `examples/agents/claude-code.yaml` has that shape — `write: [..., "/tmp/"]`, `net: allow: []` — so at
  tier 2 it handed the agent every root-only unix socket, and at tier 1 every socket its uid can open, R11 aside.
  Now the relay resolves the name as the task, on a thread holding the task's credentials, admits the socket it
  resolves to, and connects to that inode (R11); a connect it cannot make as the task is refused
  (`relay-credentials`). The Open entry that deferred the credential half is closed by the same change.
  Alternatives measured against it: `CONTINUE`ing unix connects lets the kernel re-read a `sun_path` a sibling
  thread can rewrite after the decision, which below ABI 9 nothing else checks (I2); refusing declared unix
  relays at tier 2 would break every declared socket and every `multiprocessing` or Ray socket under a write
  directory there. `TestUnixConnectIsDecidedOnTheResolvedSocket`, `TestUnixRelayFailsClosedWithoutTheTask`,
  `TestConnectUnixAsOnTheRealKernel` and `TestIntegrationUnixRelaySymlink` pin the resolution unprivileged;
  `TestIntegrationUnixRelayAsTask` (supervisor) and `TestIntegrationRunAsTakesTheTaskCredentials`
  (`internal/platform/sys`) pin the credentials as root in the guest. The main thread must never be the one
  switched: the first guest run switched it, the runtime parks rather than destroys a main thread whose locked
  goroutine exits, and `/proc/<pid>/status` then reported uid 1000 for the whole process.
- **`AF_UNSPEC` in a send was continued under no `net:` (R4, R7, E4, R13b).** Pass 2 exempted undecidable
  families from the refusal under no `net:`, and `AF_UNSPEC` with them: `sendto(AF_UNSPEC, 203.0.113.9:8080)` on a
  UDP socket was `CONTINUE`d and recorded `observed`, `dst: unspec`, while on 6.17 `udp_sendmsg` delivered the
  payload to the `sockaddr_in` behind the family word. Of the two fixes offered — refuse it, or record the
  embedded address the kernel sends to — the refusal is taken: which address those bytes name depends on the
  socket's domain and protocol, which this tier never reads, and a `NULL` address or `AF_INET` loses nothing.
  Every other family this tier does not parse is still continued under no `net:`, and a `sendmmsg` batch is now
  read past one of those to reach an `AF_UNSPEC` message behind it. `TestUnspecIsOnlyADisassociationInConnect`
  runs every send form under both contracts; `TestSendsWithNoNetSection` pins the sendto and sendmmsg rows,
  including the no-`net:` exemption for an unrecognised family, which no test pinned before.
- **R11 named a rule the refusal did not carry.** A relative `sun_path` whose cwd could not be read was refused
  `unmatched` by `decideUnix`, not `path-unreliable` as R11 said: `relayAddr`'s guard was never reached. It is
  refused `path-unreliable` now, and `relayAddr` is gone with the relay that needed it.
- **Unqualified "never CONTINUE" statements (R4, R5, R25, E4, §7, I2, R30).** Each now names the run it holds
  for: R4's relay and E4's refusal of an unknown family under a `net:` section, R5, R25(b) and §7's panic row
  outside an observe run. I2 and R30's refusal lists are examples, now with `path-truncated` and
  `relay-credentials`; the batch comment in `send.go` says each message's line. The `best_effort` note in the
  corrections above said connects never carry it; under no `net:` they do.
- **`WAIT_KILLABLE_RECV` qualifications left out the race `cce436aa` fixed (E35).** On a 5.19+ kernel without
  it, a non-fatal signal that lands as the answer is sent restarts the syscall after `NOTIF_SEND` succeeded, with
  no `result_unknown`. E35 and the comments on `relayOrphaned`, `Metrics.Orphaned`, `relayCeiling` and
  `ResultUnknown` now say so; `Metrics.Orphaned`'s comment no longer breaks mid-sentence.
- **R20 described routing the launcher never did (R20, E16, §10, §11).** A nested run fails at startup with
  `EBUSY` → `launch.ErrChildSeccomp`, exit 125 (reproduced from a binary of the tree); R20 and E16 said its
  notifications reach the ancestor's `Loop`, and R30 cited R20 for the failure. Fail-closed is what runs, so R20,
  E16 and the §10 test line now say it, and §11 records the three documents that still describe the routing.
- **`rmdir(2)` and `open_by_handle_at(2)` left no line (R1).** x86-64's `rmdir` was notified nowhere, so glibc,
  Python and coreutils deleted directories unrecorded in every tier and under `--observe`; it is notified and
  recorded as `unlinkat(AT_REMOVEDIR)` is. `open_by_handle_at` opens from a handle no line can name; it gets
  `ENOSYS` from the filter, like `openat2` (enforce-landlock R10).

## Corrections: supervisor policy, the model host (2026-09-23)

- **A direct connect to the model host went around the forwarder with no `net:` section (R7, R4, R9, security).** With no `net:` section every connect was `CONTINUE`d and recorded `allow`/`unmatched`, the
  declared `models[]` host included, so under `capture: forwarder` the agent reached the model uncaptured: kt2's
  forwarder half failed on every kernel-matrix row and on the host, where it had passed before "no `net:` — deny
  nothing" was implemented. Fail-closed: a `models[]` host:port stays refused to the agent unless
  `net.allow` names it, in this loop (the `models[]` guard, R7), in `agent.Evaluate` (`GuardedModels`, `evalGuard`)
  and so at tier 2, whose network programs stay detached for such a contract and whose verdict for it is this
  loop's. SEMANTICS §1 now gives "no `net:`" that one exception. The guard is held like any decision — relayed, not
  continued, on an IP socket — since continuing the other connects would let a sibling thread swap the endpoint in
  after the check. Alternatives measured against it: reading "no `net:`" as `net: {}` under `capture: forwarder`
  refuses every other host too, which SEMANTICS §1 does not say; a tier-2 kernel row for the endpoint needs a
  default-allow program the BPF maps cannot express (they refuse on a miss). kt2 passes again: the forwarder half
  at tier landlock on the host, and both halves at tier cgroup as root under `--sudo` in the guest.
- **An absolute `sun_path` from another mount tree was decided on a string (R11, security).** `connectUnixAs`
  admitted the path `readlink(/proc/self/fd/<n>)` reported for the inode the task's walk reached, and matched it
  against this process's policy paths. From a task whose mount tree is not this process's that string need not
  name the inode here — `d_path` builds it from the task's own mounts — and the comment on the `/` check claimed
  that check caught such cases, which `d_path` makes false. The path is now walked again in this process's view,
  following no symlink, and must reach the same device and inode (`sameInodeHere`), or the connect is refused
  `path-unreliable`; R11 states the assumption. `TestSameInodeHere` pins the comparison on the real kernel and
  `TestUnixRelayFailsClosedWithoutTheTask` the refusal; `TestIntegrationUnixRelayOtherMountTree` reproduces the case
  as root in the guest.
- **A magic link was answered `ELOOP` and recorded `allow` (R11, I3).** The relay refuses to follow one, and the
  task's own lookup would have followed it, so the `ELOOP` was this loop's refusal presented as the kernel's answer.
  It is refused `path-unreliable` with a refused line; a genuine symlink loop, which the relay cannot tell from one,
  is refused the same way.
- **R11 overstated when `relay-credentials` refuses at tier 1.** It said whenever the task's credentials differ from
  this process's; a task whose ids and groups are this process's and whose capabilities are only larger is connected,
  with the capabilities both hold. R11 and the §7 row now say when the refusal happens.
- **`TestConnectUnixAsOnTheRealKernel` failed under the documented on-disk `TMPDIR`.** Its sockets were bound under
  `t.TempDir()`, whose test-named path overflows `sun_path` there; it binds under a short `os.MkdirTemp` directory,
  as the integration test beside it does.
- **Still disagreeing, outside this document.** agent-contract.md R15 and its §11 entry
  still say two kernel checks are stricter than a no-`net:` allow (the abstract scope and `RESOLVE_UNIX`); only the
  scope is now (enforce-landlock R6), and neither mentions the `models[]` guard. ARCHITECTURE §3, runtime-launch.md
  case 6 and P0-DESIGN §2.6 still disagree with R20 (a nested run fails with `EBUSY`) and with enforce-landlock R10
  (`open_by_handle_at` joins the `ENOSYS` set). capture-derive.md R38 and kt2's header say the forwarder port is the
  only compiled `net.allow` entry for the model host once `capture: forwarder` is active, which is true under a
  `net:` section; with none, the refusal is the `models[]` guard's (`rule: models[<host>:<port>]`), at tier 1 and
  tier 2 alike, by address rather than by port or by kernel row.

## Corrections: supervisor policy, the `models[]` guard (2026-09-23)

- **The `models[]` guard matched only the address as written (R7, security).** The kernel
  sends a connection to the unspecified address to loopback, so with the guard on 127.0.0.1:8443 a
  `connect(0.0.0.0:8443)` was relayed, returned 0 and was recorded `allow`/`unmatched`; `[::]` against `[::1]` and
  `::ffff:0.0.0.0` did the same, and a copy of kt2 whose agent connected to `0.0.0.0:$port` failed its forwarder
  half. A loopback endpoint now matches every loopback and unspecified address on its port, in this loop and in
  `agent.Evaluate` alike (`agent.GuardAddrMatches`), and a `localhost` name is loopback without a lookup. A guarded
  name keeps every address it resolved to during the run: `dns.Set.Refresh` replaces, so the deny list forgot an
  address the agent could still hold. R7 and SEMANTICS §1 now list what the guard does not refuse — the model is
  refused completely only by a `net:` section. `TestIntegrationModelGuard` reproduces the bypass on the real kernel.
- **"TCP and UDP alike" was false for unconnected datagrams, at tier 2 as well (R7, R13b, R18).** A datagram to the
  endpoint was continued under R13b and recorded `refused` with `best_effort`, so QUIC over an unconnected socket
  reached the model; at tier 2 no `cgroup/sendmsg` program is attached for this contract, so that `CONTINUE` was the
  tier's verdict. Under the guard such a datagram is now refused with R10's errno, and a datagram `sendmmsg` batch
  carrying one anywhere the kernel sends is refused whole; R13b and R18 name the exception.
- **Parts of the guard had no test.** The guard's clause in `refusesUndecidable` is pinned by an unparsed family on a
  connected stream socket under the guard, which R13a would otherwise have continued; `Run`'s refresher by a name
  whose first lookup failed and that resolves on it (`Options.modelRefresh` shortens the tick for the test); and
  `Loop.guarded`'s key by an `UpdatePolicy` whose table guards other endpoints.
- **R7 and SEMANTICS §1 said `Evaluate` and the run agree on a literal address on a named endpoint's port.**
  `Evaluate` refuses it for the whole run, having no lookup; the run refuses only the name's addresses once it has
  resolved. Both now say so: for an address `compile --test` can refuse what the run admits, never the reverse,
  and for an alias of the endpoint's name it answers `allow` where the run refuses the address.
- **Two unit tests failed under a `TMPDIR` with a symlink in it.** `TestSameInodeHere` and
  `TestConnectUnixAsOnTheRealKernel` built expectations from the unresolved temporary path, while `sameInodeHere` and
  the relay's walk see the kernel's; both now resolve it first. The integration harness binds under a short
  directory of its own for the same `sun_path` reason as the unit test above.

## Corrections: exec and keyring escapes (2026-09-23)

- **An anonymous-image exec ran while the ledger read `refused` (R16, R16b; security).** A static ELF written
  to a `memfd_create(2)` region and run with `execveat(fd, "", AT_EMPTY_PATH)` — or `execve("/proc/self/fd/N")` —
  executed under a tier-1 contract that named only `python3` in `exec.allow`, and the seccomp handler, which answered
  `CONTINUE` trusting Landlock's `EXECUTE` bit, recorded it `refused reason=exec-not-allowed`: Landlock's `file_open`
  hook runs on the exec open but allows the memfd outright (`is_nouser_or_private()` matches its `SB_NOUSER`
  superblock), so the exec both ran and was falsely logged as blocked. The first fix recognised the image only when
  `AT_EMPTY_PATH` was set or the path began with `/proc/{self,thread-self,<tid>}/fd/N`, and continued every other
  spelling as an unmatched exec recorded `refused`: `/dev/fd/N`, a symlink the agent made to a descriptor,
  `/proc/self/task/<tid>/fd/N`, `/proc/<tgid>/fd/N` from a non-leader thread and a dirfd-relative `execveat` all ran
  the memfd at tier landlock and, as root, at tier cgroup. It also `path.Clean`ed the readlink, so a memfd named
  `/../<dir>/python3` read as a disk path — a PATH-search candidate, continued as an observed probe — and it took
  the descriptor on `AT_EMPTY_PATH` alone although the kernel honours the flag only for an empty pathname. The
  decision is now R16b's: the exec is walked as the task's lookup walks it, the image is classified on its inode
  before any spelling is matched, its raw name is recorded, and every exec not matched to a grant is refused by this
  loop. `TestExecAnonymousImageBySpellingIsRefused`, `TestExecMemfdNameCannotForgeAPath`,
  `TestExecEmptyPathFlagWithAPathnameWalksThePathname`, `TestWalkExecReachesTheTasksDescriptor` (the walk against
  the kernel, from another process) and `TestIntegrationExecDecisions` (the real filter, every spelling) pin it.
- **A continued exec was recorded `refused` for granted binaries too (R16, R16b; record integrity).** The verdict was
  a string comparison against the entry's declared path, while Landlock decides on the inode, so a granted binary
  reached by its symlink-resolved path, by a symlink the agent made to it, or by a regular-file `fexecve` — the
  anonymous-exec control case, which must keep running — ran and read `refused`, as did a directly-invoked loader.
  An exec is now matched by spelling and by the inode an entry named when the run started (the binding Landlock
  holds), and what matches nothing is refused here, so no continued exec reads `refused`
  (`TestExecGrantedBinaryByAnotherSpelling`, `TestExecDirectLoaderIsRefused`, `TestExecNoContinuedRefusal`). The
  direct-loader spelling of mapped code is closed in tiers 1–2 with it; the `PROT_EXEC`-mmap spelling is not (SEMANTICS §4,
  GAPS C31). An earlier bullet here said the anonymous image "was the one" exec where the verdict asserted a refusal
  the kernel did not make; it was not, and it is withdrawn.
- **The exec decision is a mitigation, not a closure, against a racing agent (R16b).** The walk and the kernel's
  lookup after `CONTINUE` are two lookups, and a second thread can swap a descriptor or symlink between them; a
  test run won that race on its second attempt. SEMANTICS §4 and GAPS C30 now say so; tier 3's
  `bprm_check_security` is the race-free enforcement.
- **fs lines read `refused` for writes that ran (R15b; record integrity).** Auditing the other advisory `CONTINUE`
  paths for the same defect: R15/R17 verdicts were taken on the spelling, so a write through `/proc/<pid>/fd/N`,
  `/dev/fd/N`, a symlink into a write entry or a system symlink such as `/var/run` ran while its line read
  `refused`. A refusal is now re-taken where the path lands before the syscall is continued
  (`TestFSRefusalIsRetakenWhereThePathLands`, `TestFSTargetLandsWhereTheKernelWrites`). The remaining continued
  `refused` lines are R13b's unconnected datagrams, which say so with `best_effort: true`, and the races and
  bind-mount shapes R15b and R16b name — this audit covers every `CONTINUE` path of this package, and those are what
  it found.
- **The kernel keyring ran unobserved and unconstrained (R32; security).** `add_key`, `request_key` and
  `keyctl` were in neither the `ENOSYS` nor the notify table, so a tier-1 run planted a key and read it back with no
  ledger line. The filter now notifies the three syscalls; by default the loop refuses them with `-EPERM`, recorded
  `refused reason=read-denied rule=keyring`, the fail-closed default Docker and firejail take, and a contract's
  `keyring: true` has them continued. A continued keyring syscall — opted in, or in an observe run, where the first
  version wrote nothing and so repeated the "zero key-related events" the item reported — leaves
  `gap what=record why=keyring-<syscall>` once per binary and syscall. `TestKeyringSyscallsAreRefused`,
  `TestKeyringUseIsVisibleWhenContinued` and `TestKeyringOptIn` pin it, and the golden filter dumps carry the arms.

### Open (2026-09-22)

- **`SO_PEERCRED`'s pid still names this process (R11, I6).** The relay now runs with the task's groups and
  effective ids, so a listener's DAC check and the uid and gid in `SO_PEERCRED` are the task's. The pid in
  `SO_PEERCRED`, and the pidfd `SO_PEERPIDFD` hands out, are taken from the connecting task by the kernel
  (`init_peercred`) and name the supervisor, which at tier 2 is root. A listener that authorizes by reading that
  process's credentials — `/proc/<pid>/status`, or the pidfd — rather than the uid and gid the peer credentials
  carry sees the supervisor's. Buildable once relayed unix connects are made from a helper process that holds the
  agent's credentials (a re-exec of `tego` started per run as the agent's uid, receiving the duplicate over
  `SCM_RIGHTS`), with a guest test that a listener reading `SO_PEERPIDFD` sees uid 1000.
- **`agent.Evaluate` does not admit a unix socket under a write entry.** SEMANTICS §5, this loop (R11) and the
  Landlock builder at ABI ≥ 9 (`RESOLVE_UNIX` under every write entry) admit it; `Evaluate` matches `net.allow`
  entries only, so `compile --test` answers `refused` for a connect the run allows. Buildable in
  `pkg/spec/agent` `evalNet` once the tier split is settled: the supervisor takes the nearest filesystem entry, the
  Landlock tier grants `RESOLVE_UNIX` by union under any write ancestor, and the two differ for a socket under a
  `deny_read` inside a write entry.

## Corrections: exec floor and launcher (2026-09-23)

- **Below Linux 6.3 the memfd vector rested on the walk alone, and a hugetlb memfd passed the 6.3+ arm (R16b; security).** The design item asked for a closure at creation below 6.3 as well, "per the kernel's
  semantics": there every memfd is exec-capable, so the filter now refuses every `memfd_create` there (`ENOSYS`,
  enforce-landlock R11a) where it used to install nothing, and on 6.3+ it refuses `MFD_HUGETLB` with or without
  `MFD_NOEXEC_SEAL`, since hugetlbfs does not enforce the `F_SEAL_EXEC` the flag sets (an `fchmod` gave a sealed
  hugetlb memfd its execute bits back on 6.17 and on RHEL 9.8's 5.14, which backports the flag). The probe picks the
  arm by what the kernel accepts, not its version: RHEL 9.8's 5.14 gets the sealing arm, Amazon Linux 2023's 6.1
  the refusing one (`TestFilterMemfdArmsOnKernel`, `TestIntegrationExecDecisions` in KVM guests of both).
  `TestIntegrationExecWalkBackstop` keeps the walk exercised with no arm on every kernel.
- **The built-in `deny_write` set is refused here (R15c).** agent-contract R20 was buildable and routed to
  this component: a notified modification that reaches a target is now answered with R10's errno and recorded
  `refused` under `fs.deny_write[<target>]`, best effort against a racing path. To match where the kernel writes,
  an `O_CREAT` open is walked through a dangling final symlink to the name it creates (`FSTarget`), where the walk
  used to stop at the link's own name: a line for such an open was taken on the link, and a refusal re-taken there
  (R15b) could read `refused` for a create that landed in a write entry.
- **An admitted datagram on a guarded IP socket was continued (R7, R13b).** Continued, the kernel read its address
  again, and a sibling's rewrite to the model endpoint in between reached the model under a line reading `allow`
  — residual (d). It is now relayed on the duplicate to the address read, with the payload read; one that cannot be
  relayed whole is refused (`ancillary-data`, `datagram-size`), and every addressed `sendmmsg` batch on such a
  socket is refused whole, since a batch cannot be relayed. (This entry called (d) closed; the next section says what
  it missed.)
- **`compile --test` allowed a raw or icmp send to a guarded endpoint that the run refuses (R7).** `evalGuard`
  guarded `tcp` and `udp` only, while the run guards every IP socket; it now guards every protocol but `unix`, so
  "`compile --test` can refuse what the run admits, never the reverse" holds for raw sockets too.
- **Two test comments said the shipped kt2 used `DIRECT=0.0.0.0:$port`.** It uses `127.0.0.1:$port`; the comments
  in `models_test.go` and `models_integration_test.go` now name the copy of kt2 that did, as the pass-3
  corrections above do.

## Corrections: exec floor and launcher, continued (2026-09-23)

The section above left two defects in this component and three overclaims. The rule bodies
carry each change; this records why.

- **A `deny_write` refusal of `linkat(fd, "", ..., AT_EMPTY_PATH)` was recorded `observed`, and under `record: off`
  not at all (R15c; security).** The new name matched `.git/hooks` and the link was refused, but the empty old name
  sent `emitFS` down its unreadable-argument branch, which replaced the verdict with `observed` and the rule with
  `args-unreadable` and wrote nothing under `record: off`: the agent got `EACCES` while the ledger said nothing was
  refused (reproduced on 6.17 at tier landlock: an `O_TMPFILE` written in the worktree and linked in as
  `pre-commit`). A refusal this loop answers is now recorded `refused` under the target's rule whatever the other end
  was, and the old end of the `AT_EMPTY_PATH` form is the file the descriptor holds (`/proc/<pid>/fd/<olddirfd>`), so
  a descriptor opened on `.git/config` cannot give it a second name either. `TestDenyWriteRefusedBySupervisor` runs
  every row under `record: summary` and `record: off`, with the `AT_EMPTY_PATH` rows and an unreadable old name;
  `TestIntegrationDenyWrite` runs them on the real kernel.
- **Residual (d) of R7 was called closed while an unaddressed `sendmsg` on a guarded socket was continued (R7,
  R13b; security).** The datagram relay covered a `msghdr` whose `msg_name` was set when this loop read it; one read
  with none was continued before the socket was looked at, and the kernel's second copy of the header then sent to
  whatever a sibling had written there, the model endpoint included, with no line. It is now relayed with no
  address on a guarded IP datagram, raw or seqpacket socket (`sendUnaddressed`). The unaddressed batch cannot be
  closed the same way — refusing it refuses glibc's DNS, and a batch cannot be relayed — so R7 lists it as residual
  (d), open, with its condition. The same header copy let a `MSG_FASTOPEN` send with no address connect to a host
  nothing decided (R12, an older gap): under a `net:` section or the guard such a `sendmsg` on an
  IP stream socket is now relayed with no address and the batch refused. `TestUnaddressedSendMsg`,
  `TestUnaddressedFastOpenBatch` and `TestIntegrationModelGuard`'s unaddressed checks pin it.
- **The `exec.anonymous` warning said the capability line reports `exec.deny` `false`**, as did the
  `ExecSection.Anonymous` comment and R16b. That holds at tier 1 only: the tier-2 handle does not yet narrow the row
  by the inherited one (enforce-landlock R11a). All three now say so.
- **The whole-datagram check on `sendmsg`'s gather had no test.** Forcing `whole` true left the suite green; the
  addressed and unaddressed forms now have rows for iovecs past `sendBytes`, an `iovlen` past `msgIovs`, an
  unreadable iovec array or buffer and a `NULL` base, each refused `datagram-size` with nothing sent.
- **GAPS C30 and enforce-landlock R11a listed RHEL 9 among kernels without `MFD_NOEXEC_SEAL`.** RHEL 9.8's 5.14
  backports the flag and gets the sealing arm in a guest; the probe, not the version, decides, and both documents
  now say so.

## Corrections: exec floor and launcher, the last of them (2026-09-23)

One more way past R15c remained, with a relay that could send this process's own
memory, and gaps in tests and wording. The rule bodies carry each change; this records why.

- **A non-dumpable target wrote past the `deny_write` set (R5, R15c; security).** A modification whose pathname
  could not be read matched no target and was continued under R5's record-only answer. At tier 1,
  `prctl(PR_SET_DUMPABLE, 0)` denies this unprivileged process every `process_vm_readv`, so one call let every write
  through, a hook included, under a line reading `observed` (reproduced on 6.17: `TestIntegrationDenyWrite`'s
  non-dumpable target wrote `.git/hooks/post-merge` with the refusal removed). In a run whose set is not empty such a
  modification is now refused, `rule: args-unreadable` or `path-truncated`; the kernel's own answer to a name it
  cannot read is `EFAULT` or `ENAMETOOLONG`, and the cost, a non-dumpable process at tier 1 modifying nothing the
  filter notifies, is stated in R15c. `TestDenyWriteRefusesAnUnreadablePath` pins it.
- **R15c's residuals left out a rewrite of the pathname in memory.** A sibling thread or `CLONE_VM` child that
  rewrites the string between this loop's read and the kernel's own needs no filesystem write, and defeats the
  `AT_EMPTY_PATH` reading too; R15c, the `denyWrite` comment and SEMANTICS §2 now name it.
- **A relay passed `MSG_ZEROCOPY` through (R7, R12, R13b; security).** With `SO_ZEROCOPY` the kernel may transmit
  from the pages it is given after the call returns, and in a relay those were this process's heap, which Go may
  reuse before the transmission: supervisor memory could go to a peer the agent chose, and since the section above every
  datagram on a guarded IP socket takes that path. A relayed send carrying the flag is now refused, `rule:
  zerocopy`. `TestRelayedSendRefusesZeroCopy` pins it, and so does `TestIntegrationModelGuard` on the real kernel,
  where with the refusal removed the datagram arrived.
- **Two of `gather`'s whole-datagram checks had no test.** A buffer cut short by the end of its mapping reads short
  without failing, and a datagram whose `sendBytes` is reached with iovecs left is not whole; both shapes are now in
  `gatherShapes`, and each fails with its check removed.
- **SEMANTICS §1 did not tell policy authors what else the guard refuses.** It now names the datagram `sendmsg` with
  control messages, the datagram that cannot be relayed whole, the relayed send with `MSG_ZEROCOPY` and the
  addressed `sendmmsg` batch, and says `compile --test` cannot show them.
- **Version-keyed memfd wording and "RHEL 9's 5.14".** The filter and arm comments now say "where the kernel honours
  the flag", as the probe decides, and the backport is RHEL 9.8's: RHEL 9.0 and 9.1 shipped before upstream 6.3,
  and only 9.8 was checked.

- 2026-10-01, R7/R13c review closure: unaddressed guarded IP non-stream batches return `ENOSYS`; guarded launches configure individual DNS queries to retain compatibility and closes the mutable-header batch gap. Earlier historical notes describing that gap as open are superseded by the rule above.
- 2026-10-05, R13b: a network gate relays an admitted addressed datagram on an IP socket only; on a unix socket it is continued as R13b says. It was relayed from this process, which sent a relative name from its own cwd, an abstract name past the agent's Landlock scope and, at tiers 2/3, to root-only sockets under its own credentials.
- 2026-10-05, R7: a launch whose gate scores `net` actions gets `RES_OPTIONS` `single-request`, as a guarded launch does; with capture uprobe or off, or no `models[]`, its glibc lookups failed on the gate's `sendmmsg` `ENOSYS`.
- 2026-10-05, R9/R12/R13b (ADR 0041 D6): under a network gate an admitted connect, Fast-Open send or addressed datagram on an IP-domain socket (`SO_DOMAIN`, not the copied family) is relayed with the scored copy, never continued, and a source-routed socket is refused `relay-source-routed`. Under a contract with no `net:` section a sibling rewrote the address past the gate after `CONTINUE`.
- 2026-10-05, R9 (ADR 0041 D6): the source-route read was a snapshot a sibling's `setsockopt` could race before the relayed call; under a network gate the filter now refuses the options that set a route (enforce-landlock R11b), and the read decides a socket that carried one before the filter applied.
- 2026-10-05, R15c (ADR 0041 D1 (a)): at tier landlock and on tier cgroup's listener this loop again refuses the
  built-in `deny_write` targets for a run that starts, best effort and disclosed, as before 2026-10-03; the text said
  every such run was refused before launch, which now holds only under `fs.assurance: kernel`.
- 2026-10-05, R13b, R18 (ADR 0016's dated note): a datagram the run's kernel program
  refuses (`Options.KernelDatagrams`: UDP under `cgroup/sendmsg4`/`6`, a unix name under `cgroup/sendmsg_unix` or the
  plane's `socket_sendmsg`) is refused here with that program's errno and recorded once, without `best_effort`; an
  unlisted UDP or unix destination was recorded refused with `best_effort` beside the kernel's enforced refusal, and
  a non-canonical unix name allow. Measured first in the 6.17 guest: the root cell's three lines carried
  `best_effort: true`, one of them `verdict: allow`, for datagrams the agent saw fail `EPERM`.
- 2026-10-05, R13b, R22: `BenchmarkRelayDatagram` (continued, refused for the kernel, relayed under
  the guard) and `TestIntegrationUDPFlood` (10,000 datagrams a second for 10 s, no backlog over R22's soft budget)
  measure the datagram paths; the figures are in R13b.
- 2026-10-16, R16b (0), R28, R24: an exec whose pathname names nothing (its walk met `ENOENT` or `ENOTDIR`) is a miss,
  answered with that errno by this loop in every run and written as no line at any record level, counted in
  `run_end.supervisor.exec_missing`; a PATH search wrote one refused, observed or allowed line per directory tried
  (`TestExecMissWritesNoLine`, `TestExecMissKeepsEveryRefusal`, `TestIntegrationExecMissWritesNoLine`,
  `TestPlaneExecMissWritesNoLine`). The same day: an observe run answers a miss with its errno
  too (`respMiss`, no refusal), since a continued miss is a second lookup a renamed-in file wins with no line
  (`TestExecMissObserveAnswersErrno`, `TestIntegrationExecMissObserveRace`, `TestPlaneExecMissObserveRace`).
- 2026-10-16, R16b (the walk, (0)): a non-leader thread's top-level `/proc/<tid>`
  is the task's own, so a miss behind its links is `ENOENT` with no line, not `EACCES` with one; a walk that fails at
  any automount point (`STATX_ATTR_AUTOMOUNT`: NFS, CIFS and FUSE submounts, debugfs's `tracing`), not only in an
  autofs directory, is no miss and is decided and recorded as before (0); a directory on FUSE, NFS, SMB or Ceph is
  unsure whatever its mode bits; and a procfs directory of another thread group (`/proc/<pid>/fdinfo`, whose 0555
  bits hide a ptrace check) is an unsure step at every tier. Each closed a place where the walk's answer differed from
  the kernel's: a miss for an existing file under an automount point, and an existence oracle on a server's
  directories and on another process's open descriptors (`TestExecImageProcDirsOfAnotherProcessAreUnsure`,
  `TestExecImageServerFSDirectoriesAreUnsure`, `TestExecImageAutomountPointFailureIsNoMiss`,
  `TestIntegrationExecProcDirOracle`, `TestPlaneExecProcDirOracle`, `TestPlaneExecAutomountIsNoMiss`).
- 2026-10-16, R16b (the walk): the cost of an unsure walk's `EACCES` is stated for each
  run shape. A refusal line and 126 hold only where the supervisor decides the run's execs; with no `exec:` section
  the exec is continued under an `allow` line and the kernel answers its own errno, and a decision plane with no
  command rules and no exec gate takes it through the fast handover. No behaviour changed
  (`TestExecUnsureWalkPerRunShape` pins the shapes).
- 2026-10-16, R16b (the walk): the search check reads a directory by its mode bits only on
  a closed list of filesystems whose permission operation is `generic_permission` over what the walk reads
  (`modeBitsFS`); every other filesystem, kAFS, 9p, Coda, eCryptfs, ntfs3, ZFS and any unnamed one beside FUSE, NFS,
  SMB and Ceph, is unsure whatever its bits, so a root walk's miss there no longer tells the task whether a name
  exists in a directory the server refuses it (`TestExecImageServerFSDirectoriesAreUnsure`).
- 2026-10-17, R16b (0): a `..` step that fails at an automount
  point is no miss, as a failed name lookup there is: at tier landlock `sub/../tool` through an idle NFS submount stub
  (no lookup operation, so `..` fails `ENOTDIR`) was a miss with no line where the kernel's walk mounts the submount
  and finds the tool (`TestExecImageDotDotOutOfAnAutomountStubIsNoMiss`). The text now says the walk leaves only a
  positive automount point unmounted: an indirect autofs map's key is mounted by the walk's own lookup, a residual
  stated in (0).
- 2026-10-16, R13b, R18: an unconnected datagram whose destination the policy
  refuses is refused with R10's errno, one enforced line, nothing sent; a `sendmmsg` batch that carries one is
  refused whole. Every such datagram was continued under a refused line marked `best_effort`, so `net.dns.mode:
  off` recorded a lookup from an unconnected socket and the resolver answered it. `BenchmarkRelayDatagram/refused`
  on the test machine (6.17, load near 14, median of five runs of 20,000): 65.1 µs before (continued), 39.2 µs after
  (refused), 1,496 and 1,481 B/op, 17 allocs/op both; the continued path is unchanged code (73.4 and 62.8 µs, the
  difference is load).
- 2026-10-16, R11, R11a: the implicit admit of a socket under a write entry
  holds only for a socket a process of the run bound, recorded at its bind (enforce-landlock R11c) and matched
  through `sock_diag`; any other socket there is refused `unix-foreign`. It admitted every socket under a write
  entry as one "the run created", and Codex's interface reached its app-server's control socket in `CODEX_HOME`
  that way.
- 2026-10-16, R11a: R11a's work is bounded per notification. A recorded socket's binding is kept
  once seen and looked up again only when it names the file decided; every question one notification asks (one per
  addressed `sendmmsg` message) shares one pass, so a socket is looked up at most once per notification; at most 256
  lookups per notification may answer "bound to nothing", past which the decision is refused `unix-origin-unread`;
  a full set is pruned at most once a second. A decision about a file no recorded socket was bound to looked up every
  recorded socket, once per message, under the set's lock: up to 266,240 lookups for one batch.
- 2026-10-17, R1 (ADR 0018 (7)): `setsockopt` is dispatched, for `TCP_ULP` alone, refused
  `ENOENT` and recorded; a ULP had turned an admitted TCP socket into `AF_SMC`.
- 2026-10-17, R1, R2: the `TCP_ULP` name's read for the line was a bare `ReadMem` with no
  `ID_VALID` before or after it, so a trapping thread that died and whose pid was reused had another process's bytes
  recorded as the name; it is a reader's `blob` now, bracketed on both sides (`TestTCPULPNameReadIsBracketed`).
- 2026-10-16, R11a: the binding's device is compared with the file's superblock device read
  from mountinfo, not with `st_dev`, which never matched on btrfs (every socket the run bound there was refused
  `unix-foreign`), and btrfs subvolumes are told apart by the directory device recorded at the bind; the path
  confirmation, which checked a path the run controls, is gone, so a renamed socket is the run's and a file with an
  inode wider than 32 bits is refused `unix-origin-unread`; a bind that cannot be recorded (a non-dumpable process at
  tier landlock, ssh-agent) refuses `unix-bind-unrecorded` and a datagram to a name that names nothing `unix-absent`
  with its lookup's errno, where both read `unix-foreign`; the residual names the rename and symlink swap a datagram
  is exposed to, and `io_uring` sends and binds at tier `bpflsm`.
- 2026-10-16, R13b, R22: `TestIntegrationUDPFlood`'s two budgets (the target at most a
  tenth behind its 10 s schedule, a notification held under R22's 200 µs on average) are asserted as written, on the
  wall clock, in budget mode (`TEGO_TIMING_BUDGETS=1`: `scripts/timing-budgets.sh`, first in CI's bench-gate job on
  its own runner, and `make budgets`); every other run holds the same figures to ten times them, 110 s and 2 ms, and
  the count, line and refusal checks hold in both (docs/BENCHMARKS.md, "Timing budgets in the test suites"). Under 16
  busy loops the unmodified flood took 15 s with a 120 to 130 µs mean hold: a machine that cannot keep 10,000
  datagrams a second whatever the loop costs. A handler slowed by a 60,000-round loop at the top of `Loop.handle`
  fails budget mode with the host as found, 12 floods of 12 (12.3 to 21.4 s); the unmodified flood passed 12 of 12 in
  the same minutes (10.0 s, mean hold 40 to 61 µs). The rate, the duration and both budgets are unchanged. ADR 0048
  C8's `TestExecCommandCostBudget` and `TestExecCommandIndexCostBudget` are asserted the same way (ADR 0048's
  2026-10-16 note).
- 2026-10-16, R7a (ADR 0041 Stage B review): the kernel recorder names the open deputy by its
  pid and its start time, and the run's reaper leaves the deputy's zombie unreaped until the run reaps it at its end.
  The recorder dropped every record of the deputy's pid for the whole run; the agent can end the deputy, the reaper
  then freed its pid, and a later process of the run given it would have had every record dropped, the plane's
  refusals among them. Shown with the reaper's exclusion removed: the killed deputy's zombie was reaped within one
  sweep (`TestIntegrationKilledDeputyKeepsItsPid`).
- 2026-10-16, R7a's held opens (ADR 0041 D4, D5): a held write-open or create
  whose descriptor fails the identity check is written as made and not delivered (`operation_completed: true`,
  `fd_delivered: false`, counted `orphaned`), not refused `held-unavailable`; and a create whose leaf appeared as a
  symlink, or an `EEXIST`, between the pin and the deputy's open is pinned and scored once more, as D4 says, where it
  answered `ELOOP` (`TestHeldCreateWhoseLeafMovesIsRecordedAsMade`, `TestHeldCreateRepinsALeafThatAppeared`).
- 2026-10-16, R7a's held opens (ADR 0041 D3 step 1): under held completion an open an `fs.ask`
  scope or an `fs.ask_read` entry holds is refused when the gate refuses its copied name where this loop's walk of it
  landed, before a person is asked, as every other held open is; the hold scored only the name its own pin reached
  (`TestHeldAskScopeRefusesOnTheCopiedName`).
- 2026-10-16, R7a's held opens (ADR 0041 D4, D5): a held open answers as the kernel does
  for `O_CREAT` on an existing directory (`EISDIR`), `O_CREAT|O_EXCL` on `.` (`EEXIST`), an `O_CREAT` open of a name
  followed by `/` (`EISDIR`) and flags the kernel refuses before the pathname (`EINVAL`); it delivered the directory,
  or answered the walk's errno. `TestHeldOpenDifferential` gains those shapes, keeps the trailing slash its cases
  had lost to `filepath.Join`, and adds a symlink to the gated file and an append through a symlink to a `deny_write`
  target, each refused on the pinned object and each let through once that check is removed. Residual, by code
  reading: an `O_CREAT` open of an existing file in a sticky directory skips `fs.protected_regular` (ADR 0041's review
  note).
- 2026-10-16, R7a's held opens (ADR 0041 D4): a pin the deputy's walk reached by a name, whose
  last link is gone when this loop reads it, is refused `gate.unreadable`; it was taken as nameless, so the floors and
  the gate's score on the pinned object were skipped and the copied name alone decided it. The deputy's reply says
  whether the walk reached the object through a descriptor, and only such an object is nameless
  (`TestHeldPinWhoseNameIsRemovedIsUnreadable`, `TestDeputyPinSaysHowItReached`).
- 2026-10-16, R7a (ADR 0041 D2): the residual of D2's LSM label check, not built, is named in R7a's
  held note, and a run that starts its deputy on a host with AppArmor, SELinux or Smack active warns of it
  (`TestHeldLabelWarning`); the check was neither built nor listed as not built.
- 2026-10-16, R11a: the path of each unrecorded bind is `stat`ed at most once per notification,
  outside the set's lock. The `stat`s were remembered only until the set changed, which any bind another worker
  recorded did, so a binder racing a `sendmmsg` batch to foreign sockets restored a `stat` of up to 256 paths the run
  chose per message, under the lock (16,896 for one notification; about 4.2 s of the lock for deep paths); "`stat`ed once" held only with no concurrent bind.
- 2026-10-16, R11, R11a (ADR 0041's note of that date): every unix pathname — a connect's, an addressed datagram's, a bind's — is resolved
  by one walk in the task's own view (`unixWalk`: from `/proc/<tid>/root` beneath it or `/proc/<tid>/cwd`, magic
  links refused, a failed lookup walked again a component at a time with procfs's `self` answered for the task, a
  walk that ends on procfs refused) and decided on the identity of what it reaches. A datagram is matched by the
  socket its name reaches, not by its spelling: a symlink at a declared name, a `..` after a symlink and a
  `/proc/self` link sent it outside every entry under an `allow`, and are refused (`unmatched`, `path-unreliable`);
  a declared entry reached through a symlinked directory matches at its resolved path. A bind records its name and
  the directory the task's lookup reaches, and which recorded bind took is the one whose name `sock_diag` reports
  (`UNIX_DIAG_NAME`): a second bind after a failed one is settled correctly, a rewritten address or a swapped
  descriptor leaves the socket unattributed (`unix-bind-unrecorded`), and a magic link, an unwalkable directory, or
  a relative name after a bind whose socket was not read leaves its directory unknown, refused `unix-origin-unread`
  where the subvolume decides. Residual (4) is now the run changing the filesystem between the two walks of one
  name. The superblock and inode number settle a file where `st_dev` is the superblock's, without the directory. An
  unprivileged supervisor's dumpable rule is stated as what it is: with `CAP_SYS_PTRACE` a non-dumpable child's bind
  is read and its socket is the run's (`TestUnixForeign` as root).
- 2026-10-17, R22: the flood's 110 s unit-gate ceiling can be reached. The harness
  killed the target at its 60 s helper timeout, so a flood slower than that failed on the report the kill cut off
  ("target report: EOF"), never on the pace budget, and the documented 110 s was not the bound applied (stricter, not
  looser). The flood's target now runs for the pace's ceiling plus that timeout, 170 s (`harnessOpts.timeout`), and a
  target still sending when it is killed is judged on the time it had run since the ack (`harnessOpts.outOfTime`),
  which is past the Limit and the ceiling, before the harness fails on the missing report. Copies of `Loop.handle`
  that sleep 0.7 ms and 1.2 ms a notification failed on the pace ceiling's own message: the first finished in 120.3 s
  ("over the unit gate's 1m50s ceiling"), the second was killed at 170 s and judged on 2m50s; the code before this
  change failed the 1.2 ms copy only with "target report: EOF" at 60 s. No budget changed. Under 16 busy loops in a
  4-vCPU KVM guest the unmodified flood took 12 to 88 s against the 110 s ceiling, with a mean hold of 67 to 589 µs
  (three sweeps of 28 runs; the 88 s in one run of 84, while other work loaded the host too): the pace is a pipeline
  across the target, the kernel and the loop's workers, which no one thread's own time measures, so its unit-gate
  margin is the machine's (docs/BENCHMARKS.md, "Timing budgets in the test suites"). That
  margin is 80% (88 s against 110 s), so a host oversubscribed past four runnable loops a vCPU can fail the flood in
  the test suite with no regression. The figure that leaves the machine out, the loop's workers' summed
  own time per notification held to ten times a per-notification limit from the 10 s schedule beside the 110 s wall
  clock, needs the loop to lock its workers to their threads while the test runs, and is not built; the 11 s Limit is
  unchanged.
- 2026-10-17, R7a's held opens (ADR 0041 Stage B review): an open is held when either kind
  the gate scores it with can score to `allow` or above (*amended 2026-10-20*, ADR 0007) (`openMayEscalate`), and the pinned object is scored as the agent's
  own open of it is (`scoreOpen`), so a read-write open is held and scored by the read predicates too; under a read
  gate alone it was not held, and under a read and a write gate it was scored by the write predicates alone
  (`TestHeldReadWriteOpenIsScoredByTheReadGate`). A held gate ask's alternate is checked with `alternateCheck`, the
  gate included, at answer time as on delivery (`TestHeldGateAskTakesAnAlternate`).
- 2026-10-17, R7a's held opens (ADR 0041 D2): every process of a held run is in the deputy's
  Landlock domain, since the run's filter answers the Landlock syscalls `ENOSYS` (enforce-landlock R10); a process that
  made a domain of its own was held only to the run's for its held opens.
- 2026-10-17, R7a's held opens and the copied path's gate (ADR 0041 D4, Step 1): an open that
  reads a regular file with no name left, reached through a descriptor, on a filesystem with names (not a memfd) is
  refused `gate.unreadable` when a read gate scores it, held or copied; it was nameless, scored on its procfs spelling
  and delivered or continued, so a gated file opened write-only and unlinked could be read. A floor refusal this loop
  does not enforce no longer skips a gate without facts (`TestGateReadRefusesAReopenOfAnUnlinkedFile`,
  `TestHeldPinWhoseNameIsRemovedIsUnreadable`).
- 2026-10-17, R7a's held opens (ADR 0041 D5): the open deputy's walk refuses to follow a trailing symlink that
  `fs.protected_symlinks` refuses (EACCES) and any symlink on a `nosymfollow` mount (ELOOP), as the task's own open
  does; it followed both and delivered the target (`TestDeputyWalkFollowsLinksAsTheKernelDoes`, and as root
  `TestHeldOpenDifferentialAcrossMounts`, which also covers bind mounts, overlayfs and a hard link).
- 2026-10-17, R7a's held opens (ADR 0041 D4; the residual): a held `O_CREAT` open (no
  `O_EXCL`) of another user's existing file or FIFO in a sticky world-writable directory is `EACCES`, as
  `fs.protected_regular` and `fs.protected_fifos` answer the task's own open; the deputy's reopen through
  `/proc/self/fd` met no sticky directory and succeeded (`TestStickyCreate`, `TestHeldOpenDifferentialAcrossMounts`).
- 2026-10-17, R7a's held opens (ADR 0041 D4, D5; a correctness review of the merged tip): a held open answers as the
  kernel does where the copy or the start of the lookup decides it whatever the name says, an empty name `ENOENT` and
  a relative name beneath a directory descriptor the task does not hold `EBADF`, before the copied name is scored,
  which refused both `gate.unreadable`; and a final symlink that an open needing a directory (`O_DIRECTORY`,
  `O_TMPFILE`) does not follow is `ENOTDIR`, which the deputy's walk answered `ELOOP` (the pin's `Directory` bit).
  `TestHeldOpenDifferential` holds 393 shapes to the kernel's answers, a generated matrix of 23 pathname shapes by 14
  flag sets among them; the task's own `/proc/<pid>/mem` under Yama is D4's second fail-closed divergence
  (`heldFailClosed`).
- 2026-10-17, R7a's held opens and R23 (ADR 0041 D5; the same review): this loop's copy of a held open's descriptor is
  closed as soon as `ADDFD|SEND` returns, before the open's line, which can wait on the ledger's queue; the copy kept a
  FIFO's reader or writer, or an `flock`, past the agent's own close (`TestHeldOpenClosesItsCopyBeforeItsLine`). A held
  pin its task left while the deputy's reply was late is answered nothing and counts no anomaly, as any notification a
  task leaves (`TestHeldPinTheTaskLeftIsNoAnomaly`).
- 2026-10-17, R7a's held opens (ADR 0041 D3, D4; the same review): the open deputy's lookup of an open that needs a
  directory (`O_DIRECTORY`, `O_TMPFILE`) needs one too (`openat2` with `O_DIRECTORY`, and the walk ends in `ENOTDIR`
  on anything else), as the kernel's does: a symlink to a gated file opened `O_DIRECTORY` is `ENOTDIR`, where it was
  pinned and refused on the gated file (`symlink_gated_directory`).
- 2026-10-17, R11a: a bound
  socket's **directory** is attributed from the kernel's reported name only when no bind of the run went unread, the
  records of that name reached one walked device, and — for a relative name — the same bytes could not have resolved
  from another cwd. `UNIX_DIAG_NAME` reports the raw `sun_path` bytes, not where they resolved, so the earlier
  rule — trust a relative name's recorded directory when no bind had gone unread, and an absolute name's always —
  attributed the wrong directory when a sibling rewrote the socket's address to another recorded bind's bytes, when a
  descriptor was swapped onto it, or when an unread bind took it after a symlink on an absolute path changed; each
  admitted a foreign socket that repeated the run's inode number in the recorded subvolume on btrfs. Now a relative
  name's directory is unknown where the subvolume decides when this socket has another recorded bind from a cwd other
  than the matched record's, or another socket not yet seen bound recorded that name from another cwd
  (`relNameFromOtherCwd`) — the rewrite and descriptor-swap routes — while one relative bind from one cwd, and a
  second bind after a failed one from one cwd, still settle; and `unknownBinds > 0`
  leaves even an absolute name's directory unknown (an unread bind may have taken the socket after a symlink
  changed). Both fail
  closed to `unix-origin-unread` where the subvolume decides; on ext4/xfs/tmpfs the superblock and inode number still
  settle the file. Tests `TestBindRecordsTheDirectoryTheKernelBindsIn` (replaced since; the rewrite, the descriptor swap, the
  absolute-symlink-after-unread and the absolute-after-unread cases) failed before the fix, admitting the foreign
  socket `allow/fs.write`.
- 2026-10-17, R11a (ADR 0041's note of that date): a bound socket is no longer attributed to the
  directory a recorded bind's name reached. The run's sockets are the socket objects a task of the run held, bound to
  nothing, and called `bind` on (sockfs inode and cookie), with when each bind was answered; nothing of a bind's name,
  cwd or directory is recorded or walked. The file a name reaches is the socket's where `st_dev` is the superblock's
  by superblock and inode number, as before, and elsewhere (btrfs, overlayfs) only when it was born within ten seconds
  after one of the socket's recorded binds and before the socket was seen bound, and no socket outside the run shares
  its superblock and inode number in a dump of the namespace begun after the file was reached or a second after it
  was born; a file born before
  the bind is `unix-foreign`, and an unknown birth time, a shared pair, a refused or oversized dump, and a birth in
  no recorded bind's window are `unix-origin-unread`. Six orderings of a bind continued with no record and five of a
  rewrite or swap onto a recorded name, each of which admitted a foreign btrfs socket `allow/fs.write` before
  (`TestR11aDecidesTheBoundFileByIdentity`), are refused `unix-foreign` and the run's own socket admitted, which before
  was refused in most of them; the run's own socket on btrfs is refused only while a live socket outside the run
  shares its pair. Residual (4) is restated: a socket another network namespace's process binds during one of the
  run's binds at the colliding inode number. `unknownBinds`, `relNameFromOtherCwd` and `TaskCwd` are removed, and with
  them the 58 ms sweep. `TestConnectUnixAsUnderSwapsConnectsOnlyTheInodeAdmitted` races the relayed connect
  against symlink and directory swaps.
- 2026-10-17, R11a (ADR 0041's note of that
  date): a relayed connect's dump of the namespace is taken only as one pass of the kernel's walk of its socket table
  — the first datagram filled into 32 KiB, with room left for one more socket, and nothing in the next — else refused
  `unix-origin-unread`. A dump the kernel sends in several datagrams resumes each at a saved index into a hash
  bucket, so a socket that leaves that bucket in between, which the run's own churn does whenever it likes, makes it
  skip one bound throughout, and a skipped foreign socket sharing the run's socket's pair was admitted
  `allow/fs.write`; the R11a text said every socket of this namespace is in the dump. A stream or seqpacket socket's
  connect asks for the unconnected sockets only, which fit one pass up to some 600; a datagram socket's connect for
  every socket, which a busy desktop's connected streams take past one pass, refused there. A datagram's decision,
  best effort already, reads the whole list however many datagrams it takes, and what that list skips is named in
  residual (1). Rejected options (14) to (19).
  `TestUnixDumpIsOnePassOrRefused`, `TestR11aConnectDumpIsOnePass` and the connected-socket cells of
  `TestUnixDumpListsWhatAConnectCanReach` hold it.
- 2026-10-17, R11a (ADR 0041's note of that date):
  the text said a dump that lists none of the run's sockets under the pair means the socket went away. It also
  means the decision's list leaves the socket out because it cannot take the connect: a connected stream or seqpacket
  socket, which no list holds, and, since the one-pass list, a datagram socket another socket connected to, which a
  stream or seqpacket socket's connect's list does not hold. A stream connect on btrfs or overlayfs to the run's own
  datagram socket so connected is therefore refused `unix-origin-unread`, where it was admitted and met the kernel's
  `EPROTOTYPE`; the refusal fails closed and changes the errno and the line, not what is reached. Kept, and written
  down here, in R11a, SEMANTICS §5 and OPERATIONS; rejected options (20) and (21). The row "the run's own socket is
  connected" of `TestR11aConnectDumpIsOnePass` holds it (it fails when a stream connect asks for connected sockets).
- 2026-10-27, R15f (ADR 0043 C8's supervisor half and interface 1): new. At tier 2 the advisory verdict
  refuses an operation on a file a name entry covers once the walk allowed it, the listener fallback enforces the
  mutation refusals, and a directory rename that takes files out of a name entry's coverage is refused beside R15d.
  Nothing changes for a table
  without name entries, which stats no rename's source (`TestNameMoveRefusedAtTier2`). Tests:
  `TestSupervisorRefusesNameMutationAtTier2`, `TestNameMoveRefusedAtTier2`, decide's
  `TestAdvisoryFSNameMatchesEvaluateAtCgroup`, `TestAdvisoryFSNamesMutationsAtCgroup`, `TestNameMoveRefusedMatchesEvaluate`.
- 2026-10-27, R15f (ADR 0043 interface 2): a held open's completion refuses a held file a name entry
  covers `read-denied` at tiers cgroup and bpflsm, before the person is asked and again after the answer, and an
  alternate a declared name entry covers is refused there. Tests: `TestHeldAskOpenRefusesNameMatchedFile`,
  `TestAlternateRefusalNamesDeclaredNameEntries`.
- 2026-10-27, R15f (ADR 0043 interface 2 and ADR 0047): a held `fs.ask`
  mutation's completion refuses, unasked and again after the answer, a file made, removed or moved at a covered name
  and a directory move out of coverage, at tiers cgroup and bpflsm; `nameMove`'s refusal is a floor. Before, each
  merge alone was right, and together an approval made `.env.local` in an ask scope. Test:
  `TestAskMutationRefusesNameMatchedFile`.
- 2026-11-02, R13b, R22 and ADR 0048 C8 (where the budgets of the 2026-10-16 entries are asserted): CI's bench-gate
  job asserts them with `TEGO_TIMING_BUDGETS=hosted` (`scripts/timing-budgets.sh --hosted`): the flood's two budgets,
  C8's index and every C8 exec case as written, but the unguarded exec and the `#!/bin/sh` script, whose added cost is
  a handful of system calls and which missed their Limits on the hosted runner (it makes a system call at 2.5 to 2.9
  times the reference box's cost), at `testutil.HostedSystemCallFactor` (2) times their figures. The same job compares
  C8's exec path with the base commit's (`BenchmarkExecCommandCost`), which a regression of about +7 µs fails there;
  `make budgets` holds every budget as written on the reference box (ADR 0048's 2026-11-02 note).

*Amended 2026-11-03 (ADR 0069 D3(b), SEC09/SEC10; ADR 0041 D3, SEC11):* before releasing a held-read agent,
retain O_PATH identities of launch-nested deny_read targets and denied descendants, respecting nearer write entries.
Check identity before pathname on each held read and drain the protected-entry/ancestor/denied-directory watch queue
before open and after descriptor verification. After open, a getdents64 step on every watched directory waits
for earlier mutations to publish their events before the queue is drained. Unknown replacement history, lost watches, overflow or bounded-drain
exhaustion permanently refuse held reads until restart. Snapshot/watch failure or the 8,192-visited-name/watch bound refuses
launch. Close retained descriptors and watches on failed launch and after workers stop. Ordinary held write-opens
also apply liveHeld to the pinned object, and every held open reloads live blocks before delivery. If a late check
refuses after create/truncate, record the operation as completed with no descriptor delivered. Copied mutations,
previously delivered descriptors, future name-only matches outside watched launch targets and D2's LSM labels retain
their disclosed limits.
