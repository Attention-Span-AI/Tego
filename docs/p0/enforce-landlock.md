# internal/runtime/enforce + landlock backend + tier-1 seccomp filter (P0 detailed spec)

## 1. Purpose and boundaries

Owns: `enforce.Backend`/`Select` (package `internal/runtime/enforce`); the tier-1 implementation
(`internal/runtime/enforce/landlock`) that turns a compiled `agent.RuleTable` into a Landlock ruleset with
best-effort ABI degradation, and the classic-BPF seccomp program that turns write-opens, execs, connects,
datagram sends, deletes, renames, mkdirs and symlinks into supervisor notifications.

Must not own: the notification/decision loop that consumes `Handle.SeccompFilter()` (`internal/runtime/ask`/
supervisor); installing the filter or calling `landlock_restrict_self` (the child stage,
`internal/runtime/launch`, ARCHITECTURE §5 steps 5–6); tier 2/3 (`enforce/cgroup`, `enforce/bpflsm`); ledger
writes (never imports `internal/ledger` or `internal/check`); rule semantics (`pkg/spec/agent.Compile`
produces the already-validated `RuleTable`; this package only translates it into kernel objects).

Imports allowed: `pkg/spec/{agent,backend,identity}`, `golang.org/x/sys/unix`, `golang.org/x/net/bpf`,
`github.com/landlock-lsm/go-landlock/landlock`; a build with `-tags tegotesthooks` also imports `pkg/spec/config`, for
the filter test hook's AT_SECURE guard (R11). Per `landlock/doc.go`, **must not** import
`github.com/cilium/ebpf` (tier 1 emits classic BPF via `x/net/bpf` for seccomp, not eBPF — different kernel
subsystem, different library, that dependency belongs to tier 2/3). `internal/runtime/enforce` imports only
its four subpackages and `pkg/spec`; must not import `internal/check` (REPO-LAYOUT.md).

## 2. Models

Unexported except the two interfaces; nothing here is serialized (no YAML/JSON tags — this component's only
externally visible trace is `record.Event` values the supervisor emits from data this package hands it).

```go
// internal/runtime/enforce/backend.go
type Backend interface {
    Tier() backend.Tier
    Capabilities() backend.Set
    Prepare(ctx context.Context, rt *agent.RuleTable, run identity.RunRef) (Handle, error)
}
type Handle interface {
    LandlockRuleset() (fd int, ok bool)
    SeccompFilter() ([]bpf.Instruction, bool)
    Attach(cgroupID uint64) error   // landlock: no-op
    Detach() error                 // landlock: no-op
    Close() error                  // idempotent
}
func Select(m *config.Machine, rt *agent.RuleTable, probe *doctor.Probe) (Backend, []Diagnostic)
```

```go
// internal/runtime/enforce/landlock/ruleset.go
type accessFS uint64 // mirrors LANDLOCK_ACCESS_FS_*, superset across ABI 1–7
const (
    accessExecute accessFS = 1 << iota
    accessWriteFile; accessReadFile; accessReadDir
    accessRemoveDir; accessRemoveFile
    accessMakeChar; accessMakeDir; accessMakeReg; accessMakeSock; accessMakeFifo; accessMakeBlock; accessMakeSym
    accessRefer    // ABI 2+
    accessTruncate // ABI 3+
    accessIoctlDev // ABI 5+
)
type netAccess uint64 // ABI 4+
const ( accessNetConnectTCP netAccess = 1 << iota; accessNetBindTCP )
type netRule struct { Access netAccess; Port uint16 } // one landlock_add_rule(LANDLOCK_RULE_NET_PORT) per
                                                        // distinct declared TCP port — R6 (corrected)
type unixRule struct { FD int; Path string; Abstract bool } // ABI 9+ only, R21; FD unused for Abstract
type scope uint64 // ABI 6+, declared at ruleset creation, no per-rule grant
const ( scopeSignal scope = 1 << iota; scopeAbstractUnixSocket )

type entryKind uint8 // classifies why an fd is held; drives its access mask
const (
    kindWrite entryKind = iota // fs.write: full read+write+create+remove set
    kindAsk                    // fs.ask: identity only, Access=0 (SEMANTICS §3.1: ask carries no rights)
    kindDenyTarget              // deny_read node itself: Access=0
    kindDenyAncestor             // enumerated ancestor: READ_DIR only
    kindDenySibling                // enumerated sibling: tier default read set
    kindExecBinary; kindExecDir    // exec.allow entries: EXECUTE|READ_FILE
    kindExecLoader; kindExecInterp  // PT_INTERP / #! target: READ_FILE|EXECUTE
    kindMCPCommand; kindAgentCommand
    kindImplicitDeny                 // run dir, contract file, /sys/fs/cgroup, /sys/fs/bpf: Access=0
)
type openPath struct { FD int; Path string; Kind entryKind; Access accessFS }

type handle struct {
    rulesetFD int          // -1 once released
    filter    []bpf.Instruction
    open      []openPath
    net       []netRule     // R6 (corrected)
    unix      []unixRule    // R21, only populated when abi >= 9
    abi       int           // probed ABI; 0 unreachable (Select filters it out first); read by Capabilities(), R19
    caps      backend.Set
}
type abiProfile struct { Version int; FS accessFS; Net netAccess; Scope scope }

// Options seams the three Landlock syscalls for §10's unit tests (REPO-LAYOUT.md's own `New(opts Options)
// enforce.Backend` snippet for this package — corrected, Corrections C2).
type Options struct {
    syscalls landlockSyscalls // nil ⇒ the real landlock_create_ruleset/landlock_add_rule pair
}
type landlockSyscalls interface {
    CreateRuleset(attr *unix.LandlockRulesetAttr, flags int) (fd int, err error)
    AddRule(rulesetFD int, ruleType int, attr unsafe.Pointer, flags int) error
}
```

Validation: `openPath.FD >= 0` before use; `Kind` is switched exhaustively with no `default` (a new compiler
kind without a matching arm fails the build); `abi` is set once, before any `Access`/`netRule`/`unixRule` mask
is computed.

## 3. Repositories and storage

No ledger, no file, no persistent state. What is held:

- **O_PATH fds**, one per `openPath`, opened by `Prepare` in the **launcher** (parent) process before
  `clone3` — never in the child, which only inherits the copied fd table (ADR 0010). Held for every
  `fs.write`/`fs.ask`/`fs.watch` entry, every enumerated `deny_read` ancestor/sibling/target, every resolved
  exec target/loader/interpreter, the agent command, every `mcp[].command`, every pathname `net.allow`
  `unix:<path>` entry (ABI ≥ 9 only, R21), and the four implicit-deny nodes. Sequential open, single goroutine,
  read-only after `Prepare` returns. No durability needed — process-table state only; a supervisor crash loses
  it naturally and the orphan sweep's `cgroup.kill` plus the child's inherited fail-closed `ENOSYS` state
  (OPERATIONS.md) make the loss safe. Cost: one fd per entry against `RLIMIT_NOFILE` (E11), **shared with**
  every other fd the same launcher process opens before `Prepare` runs — the ledger writer's file, the cgroup
  directory fd, the run-dir lock — so `RLIMIT_NOFILE` exhaustion is a whole-process budget, not this package's
  alone (E27).
- **The Landlock ruleset**: a kernel object behind `rulesetFD`, built once via `landlock_create_ruleset` +
  one `landlock_add_rule` per `openPath` with `Access != 0`, one per `netRule` (`LANDLOCK_RULE_NET_PORT`, R6),
  and one per `unixRule` at ABI ≥ 9 (R21). Consumed once by `landlock_restrict_self` in the child, then closed
  (the kernel keeps its own reference inside the calling task's credentials from that point on — ARCHITECTURE
  §5). Not pinned (unlike tier 2/3's eBPF objects; Landlock rulesets are not `bpffs`-pinnable), never shared
  across runs.
- **The seccomp filter's `[]bpf.Instruction`**: built once, installed once by the child via
  `seccomp(SET_MODE_FILTER, NEW_LISTENER)`. Not pinned, one per run.

## 4. Functions and contracts

```go
func New(opts Options) enforce.Backend
```
Stateless constructor; no syscalls; safe to call more than once. **Corrected** (was a bare `New()` — see
Corrections C2): `opts.syscalls == nil` selects the real `landlock_create_ruleset`/`landlock_add_rule`
pair; production call sites pass `Options{}`. A non-nil value is how §10's unit tests inject fakes for R2
(ABI degrade), R3 (sibling enumeration) and R6/R21/R22 (net/unix rule counts) without root or a real kernel.

```go
func (b *Backend) Tier() backend.Tier // backend.TierLandlock, always
func (b *Backend) Capabilities() backend.Set // tier-1 row (CAPABILITIES.md), read from the probed ABI — R19
```

```go
func (b *Backend) Prepare(ctx context.Context, rt *agent.RuleTable, run identity.RunRef) (api.Handle, error)
```
Pre: `rt` already compiled/validated; called before `clone3`. Post (ok): every fd `>= 0`, `rulesetFD >= 0`
even for an empty `rt.FS` (empty ruleset + full write mask handled = "all writes refused" by omission,
SEMANTICS §1), `filter` non-empty always (tier 1 installs the record filter even with no rules, P0-DESIGN
§2.6). Post (err): one of `ErrLandlockUnsupported` (ABI probe failed — defensive, `Select` should have
excluded this backend), `ErrPathVanished` (`ENOENT`/`ELOOP` on a compiled entry, E14), fd-exhaustion wrapping
`EMFILE`/`ENFILE` (E11), `ErrRulesetBuild` wrapping a failing `landlock_add_rule` or a held descriptor lost to
another owner (§7, I12). Side effects: opens N fds;
**atomic** — any failure closes every fd opened so far before returning (no leak on partial failure), save a
number not shown still to name what it was opened on (a held number whose (dev, ino) changed or cannot be
read, a ruleset number that no longer answers as a ruleset), which may be another owner's by then and is not
closed (I12).
Idempotency: none — call exactly once per run. Timeout: checks `ctx.Err()` every 256 entries (individual
`openat` calls are not themselves cancellable).

```go
func (h *handle) LandlockRuleset() (fd int, ok bool) // ok always true for landlock; fd=-1 after Close
func (h *handle) SeccompFilter() ([]bpf.Instruction, bool) // caller must not mutate the returned slice
func (h *handle) Attach(uint64) error                     // no-op, nil
func (h *handle) Detach() error // no-op, nil
func (h *handle) Close() error
```
`Close`: closes every `openPath.FD` (best-effort via `errors.Join`, does not stop at first failure) and
`rulesetFD` if still open; idempotent (second call is a no-op returning `nil`). Called by
`internal/runtime.Run`'s shutdown after the pipeline drains (P0-DESIGN §4.1 step 5). Releases only the
launcher's bookkeeping — the kernel Landlock domain lives in the child's credentials independently.

This package prepares the ruleset and never applies it. The child stage applies it on its locked thread
(`internal/platform/sys`, `RestrictSelf`, the one `landlock_restrict_self` wrapper in the tree, R18).
A hard failure of that call (not the ABI-11 `EINVAL` fallback — an outright `EPERM`/other errno) is a
program-load error, not a target-exec error: the child stage aborts before step 8's `execve` and reports it up as
exit 125, never 126 (corrected — see §7 and Corrections C3).

The child stage's call
takes its flags from `ChildSpec.LandlockFlags`, which may carry one `LOG_*` flag: `LOG_NEW_EXEC_ON` (ABI 7,
Linux 6.15) when the machine config opts in (`landlock.audit: new-exec`, spec/config/v0; off by default), so the
kernel's audit log records the Landlock refusals the agent meets after the stage's `execve`, which by default it
does not. The stage drops, before the call, every flag its kernel's ABI does not know, so below ABI 7 the flag
costs the audit record and never the confinement, and the run records that with `gap what=record
why=landlock-audit-unavailable` after `run_start`; a flag the kernel knows and still refuses fails the stage
(`runtime-launch.md` §6 case 4). The records go where the kernel's audit subsystem sends them (auditd, or the
kernel log when it is enabled with no daemon), and Landlock logs nothing while audit is off (it counts the
refusal and returns, `security/landlock/audit.c`), so the flag is accepted and every record dropped. When the ABI
keeps the flag the launcher reads the audit state at run start and writes `gap what=record why=kernel-audit-off`
after `run_start` when it is known to be off: `/proc/self/loginuid` absent (the kernel is built without
`CONFIG_AUDIT`), a `NETLINK_AUDIT` socket refused with `EPROTONOSUPPORT` (booted `audit=0`), or `AUDIT_GET`
answering `enabled` 0 (no `audit=1` and no auditd that turned it on, or `auditctl -e 0`). The first two need no
privilege; `AUDIT_GET` needs `CAP_AUDIT_CONTROL` and a caller in the initial user and pid namespaces, so a root
run (tier `cgroup`, or tier `landlock` under sudo) gets its answer, and an unprivileged run, a file-capability
copy, or a root launcher in a container's namespaces does not. (*Amended 2026-10-05, ADR 0042 (3)(a):* a
file-capability copy is refused at start, so it never reaches this question.) Such a run writes `gap what=record
why=kernel-audit-unknown` after `run_start` instead: a kernel built with audit and not booted `audit=0` that
nothing turned on (no `audit=1`, no auditd) has audit off and drops every record, and nothing an unprivileged
process can read tells it apart from one that logs, so the run says its audit was asked for and not confirmed.
Only a run that read the audit as on writes no gap, so the commonest opt-in, an unprivileged tier-`landlock` run
on a distribution kernel with no `audit=` and no auditd, where audit is off, never reads as audited. The condition
for telling off from on there too is a kernel interface that gives the audit state without `CAP_AUDIT_CONTROL`,
which 6.17's `kernel/audit.c` does not offer (`TestLandlockAuditOptIn`, `TestReadKernelAudit`; as root in the KVM
guest on 6.17 the state read on with `audit=1`, and off with `audit=0`, whose audit socket is refused with
`EPROTONOSUPPORT`, and with neither; unprivileged it read off with `audit=0` and unknown otherwise, and as root in
a new pid or user namespace unknown; a `sudo tego run` at tier `landlock` and at tier `cgroup` wrote
`why=kernel-audit-off` in both off boots, where no `type=1423` record appeared, and not with `audit=1
audit_backlog_limit=8192`, where the refused write was one; an unprivileged `tego run` at tier `landlock` wrote
`why=kernel-audit-unknown` with `audit=1` and with neither, and `why=kernel-audit-off` with `audit=0`). The state
is read once, so an `auditctl -e 0` during the run is not seen. With no auditd the kernel prints records under
`printk`'s rate limit and holds at most `audit_backlog_limit` (64 by default) of them, and a root `tego run` first
loads and unloads the tier probes' BPF programs, each an audit record of its own, so on those defaults the Landlock
record can be crowded out: as root in the KVM guest on 6.17 with `audit=1` alone none reached the log, and with
`audit_backlog_limit=8192` and `kernel.printk_ratelimit=0` each refused write after exec was one `type=1423` record
naming `blockers=fs.make_reg` and the directory, at tier `landlock` and at tier `cgroup`, and none with the key
off. An operator who opts in runs auditd, or raises those two limits.

**Changes.**
- 2026-09-29, `RestrictSelf` removed (dead code); the seam has no restrict call; the child stage applies the ruleset.
- 2026-09-23, audit opt-in: records survive only under auditd or raised `audit_backlog_limit`/printk
  limits.
- 2026-09-23, audit opt-in (fail-closed): a root run asks `AUDIT_GET`; an unconfirmed state writes
  `why=kernel-audit-unknown` (it wrote nothing and read as audited).

## 5. Business rules

**R1 — ABI probe.** `landlock_create_ruleset(nil, 0, LANDLOCK_CREATE_RULESET_VERSION)`; positive return = ABI
number; negative (`ENOSYS`/`EOPNOTSUPP`) = unsupported, `Prepare` returns `ErrLandlockUnsupported`. `doctor`
probes the same way ahead of `Select`, so this is defensive-only in normal operation.

**R2 — best-effort degrade table** (requested rights masked against the probed ABI before any
`landlock_add_rule`; kernel additions per ARCHITECTURE §14):

| ABI | Adds | Handling |
|---|---|---|
| 1 | base FS rights | full FS set, no `REFER`, no net, no scopes |
| 2 | `REFER` | added to write masks; without it, cross-directory link/rename is refused unconditionally rather than by nearest-wins |
| 3 | `TRUNCATE` | added to write masks; below ABI 3 Landlock cannot deny truncation at all, so the seccomp filter refuses `truncate(2)` and an `O_TRUNC` open whose access mode is not `O_WRONLY` or `O_RDWR` (`O_RDONLY`, or mode 3) with `EPERM` instead (E31) — coarser than the contract, and the only way SEMANTICS §1's "`fs: {}` refuses truncate" holds on a 6.1 kernel. `ftruncate` and a write-mode `O_TRUNC` are not refused: both need a write open, which `WRITE_FILE` decides from ABI 1 |
| 4 | `CONNECT_TCP`, `BIND_TCP`, per-port net rules | one `netRule` per distinct declared TCP port, R6 (corrected); below ABI 4, no TCP rule at all — every connect lives or dies purely on the supervisor's decision |
| 5 | `IOCTL_DEV` | added only for declared `/dev` writes (rare in P0) |
| 6 | scopes | `SIGNAL`/`ABSTRACT_UNIX_SOCKET` declared in `handled_access_scope` at creation, R7 |
| 7 | audit logging (`landlock_restrict_self`'s `LOG_*` flags) | none unless the machine opts in: `LOG_NEW_EXEC_ON` with `landlock.audit: new-exec`, dropped by the child stage below ABI 7 (§4, R18); `landlock_add_rule`'s `flags` stay `0` (R20). *Corrected 2026-09-23:* this row named audit-quiet rule flags, which are ABI 10's (`LANDLOCK_ADD_RULE_QUIET`, Linux 7.2) |
| 8 | TSYNC | not implemented — no capability row claims it, and R13 already excludes `TSYNC` structurally |
| 9 | pathname/abstract `unix:` rules | **implemented** (corrected from "not implemented"): one `unixRule` per declared `unix:` entry, R21 — required by SEMANTICS §5 and CAPABILITIES.md's "unix sockets" row. `RESOLVE_UNIX` is handled, and granted under every write entry, only under a `net:` section: it is net:'s pathname-socket half, and with no `net:` no unix right is handled at any ABI (R6) |
| 10 | UDP rule types, in-kernel port | **implemented as a backstop** (corrected), layered onto R14: one in-kernel port rule per distinct declared UDP port, and `BIND_UDP` on the ephemeral port only, R22 — required by SEMANTICS §5 and CAPABILITIES.md's "UDP by port in-kernel" row |
| 11 | `NO_NEW_PRIVS` fold | handled entirely by the child stage's `sys.RestrictSelf` (R18), not ruleset construction |

Above ABI 11, clamp to the ABI-11 request (E25).

**R3 — sibling enumeration for `deny_read`.** For target `X`, walk from `X`'s parent to `/`. At every level
`L`: (1) `L` itself never gets `READ_FILE`; (2) every entry of `L` not on the path to `X` (a sibling) gets the
tier default read set — `READ_FILE|READ_DIR|EXECUTE` for a directory, `READ_FILE` only for a file (a
directory right on a file is `EINVAL`); (3) `L`, when it is an ancestor of `X` rather than a sibling, gets
`READ_DIR` (listing and `stat` work, contents do not), plus `EXECUTE` when the contract has no `exec`
section, exactly as the sibling read set does: without it an ancestor of a `deny_read` target would stop
every program beneath it from running, since the kernel needs `EXECUTE` on each directory of the path. Recurse to `L`'s parent. Rules are added from the same
held `O_PATH` fds, never by re-resolving the path string. The `readdir` that produces the sibling name list at
each level is a single snapshot taken once per level; a rule is built for exactly the names in that snapshot,
never re-read (E28). A level the launcher may search but not list (`EACCES` on the listing) has an empty
snapshot, so no sibling there is granted (E33). A target at or below **another** target is dropped before the walk (E29): walking it
would build levels *inside* the outer target, and (2) would then grant the tier read set to that target's own
contents. Landlock rules only ever add rights — an access is allowed when any rule on the path grants it — and
the outer target is denied by carrying no rule at all, so nothing on it can take those grants back. The outer
entry already denies the inner subtree, so the more specific entry adds nothing and must never subtract. For
the same reason every deny node — each target and each enumerated ancestor — is **sealed by inode**, not by
name: all targets, then all ancestors, are held and sealed before the first level is listed, and no later
grant unions onto a sealed entry. Whatever else turns out to be the same inode — a hardlink of a target
enumerated as a sibling, a bind mount of an ancestor listed as a sibling at another level, a `PT_INTERP`
resolving onto a target — a target keeps `Access: 0` and an ancestor (3)'s listing rights (I11). E32 covers an
inode an earlier stage already held, a declared grant that lands on a sealed one, and levels that lie inside a
target through a bind mount of the whole target (skipped, E32 (d)).

**R4 — unenforced under a writable parent.** If any level enumerated by R3 (target, its ancestors, or the
target's parent) lies at or below a declared `write`/`ask` entry, the `deny_read` entry is **not** added to
the ruleset at all (a broader write-side `READ_FILE` grant would union over and defeat the deny). `Prepare`
asserts this matches `compile`'s own `unenforced (landlock: parent writable)` diagnostic rather than
recomputing independently (I5). The containment question, the nesting filter (E29) and the ancestor levels (R3)
are one pure plan, `pkg/policy/fsplan` (`Build`, `FirstCover`, `Outermost`, `Ancestors`; amended 2026-10-05), which
compile's prediction reads through the decision core's `internal/policy/decide` `Unenforced`, `Outermost` and
`AncestorSet` (ADR 0028) and `Prepare` builds from the names its held `O_PATH` descriptors report
(`fsplan.Build`); the builder resolves, holds and lists, and applies what the plan answers. A held name that is not
the one compile resolved (`FSRule.Resolved`, `ExecRule.Resolved`: a grant or target moved between compile and run)
fails `Prepare` with `ErrRulesetBuild` and "recompile the contract" rather than index another subtree
(`checkHeldName`). A target whose name a `write`/`ask` entry covers is not held for the run: the name the plan reads
is taken from a descriptor opened and closed at once, and only a target the plan enforces keeps one (amended
2026-10-27; E11).

**R5 — exec grants** (`EXECUTE|READ_FILE`, never `EXECUTE` alone — `file_open` requires both under
`O_RDONLY|__FMODE_EXEC`, so a grant inside a `deny_read` leaves that entry readable at this tier: SEMANTICS §2's
stated exception; tier 2's listener and tier 3 refuse the read): the resolved inode of every `exec.allow` entry (directory entries grant the whole
subtree via one recursive Landlock rule); the `PT_INTERP` loader of each granted ELF binary, read once per
binary (absent for a static binary — not an error); the `#!` interpreter of every directly-executed script
target (agent command, `mcp[].command`, any script-resolving `exec.allow` entry) — the interpreter must
already be independently granted or `Prepare` fails closed naming it; the agent command and its own
loader/interpreter unconditionally (SEMANTICS §1); every `mcp[].command[0]` and its loader unconditionally. An
unlisted script's interpreter gets no per-script exemption — SEMANTICS §4: "An unlisted script is refused in
this tier." The `#!` line is read as `binfmt_script` reads it: the name ends at a space, tab or NUL, only
trailing spaces and tabs are trimmed, so a CRLF line's `\r` stays in the name or the argument, and the
argument is the whole remainder, one string (`#!/usr/bin/env python3 -u` asks for `python3 -u`); a name or
argument no grant covers is refused as any other. "Independently granted" is asked where the kernel asks it: `execve` opens the interpreter after
following its symlinks, and every exec grant is held on its resolved inode, so an absolute interpreter is
covered when its resolved path is a file grant's resolved path or lies beneath a directory grant's resolved
path. A `#!` under a symlinked `exec.allow` directory is therefore covered, and one naming a symlink *out of* a
granted directory is not (the kernel would refuse it with `EACCES`; `Prepare` names it instead, E14). A grant
with the same basename covers a *bare* name only, one with no slash at all: `env`'s argument, which names no file
until the run's `PATH` resolves it at exec time, is the one name nothing else can match. An absolute interpreter is
never covered by basename, and neither is a relative one with a slash (`#!/usr/bin/env sub/py`): `env` execs it
relative to the cwd with no `PATH` search, and `Prepare` cannot know that cwd, so it is not covered at all. A `#!`
naming a hardlink of a granted file under another path is the same inode, which the kernel would run, but it is
refused on purpose: `decide.Evaluate` cannot see inodes and reports that script refused, and the two must agree. The Landlock tier cannot match by name (SEMANTICS §4), so a same-named grant elsewhere, a different
inode, would cover an interpreter that `execve` then refuses. `compile`'s own check keeps the basename arm for
every name but only warns (`[interpreter]`), so `Prepare` refusing it is the fail-closed side. An exec grant
whose inode is a `deny_read` node fails closed (E32).

An `EXECUTE` rule is bound to the inode, so Landlock also allows every **hard link** of a granted binary, under
whatever name. On Ubuntu 25.10 `/usr/bin/{sleep,echo,env,ls,dd,ln,mv,…}` are hard links of one uutils multi-call
binary, so `exec.allow: [/usr/bin/sleep]` alone would let the kernel run `/usr/bin/ls` and `/usr/bin/dd`. The
contract grants a name (SEMANTICS §4; `decide.Evaluate` and tier 2's fanotify check match exec by
path, enforce-cgroup-observe), so a hard link under another name is refused at this tier too, and the refusal is the
supervisor's, not this ruleset's: supervisor R16b matches an image to a file entry on its inode *and* its resolved
path, and answers an unmatched exec itself, never `CONTINUE`d, so Landlock never decides it. That refusal is tier 1's
guard for the hard-link case; this ruleset alone still admits the inode. A symlink leading to the entry's resolved
path, and a descriptor opened by such a spelling, stay the grant they are.

The loader grant is **confined** (E29). `PT_INTERP` is a string inside a file, and a binary that lies under an
`fs.write` entry is agent-writable between runs, so the grant's *path is chosen by content* rather than by the
contract. It is accepted only when it is a regular file — a `PATH_BENEATH` rule on a directory is recursive,
so a directory there would turn a per-file grant into a subtree read grant — that lies outside every
`fs.write`/`fs.ask` entry and every `deny_read` target (an entry of `/` contains every path, so under `fs.write: /`
every dynamic binary's loader is refused), and whose inode is not itself a `deny_read` target's. The
inode check sees a target's own inode. In addition, a loader with `nlink > 1` is refused whenever an
**enforced** `deny_read` directory exists: one of its other names could be an unenumerated child of that directory.
The link count is read from the held descriptor before its rights are granted. Single-link loaders, and
multiply linked loaders with only unrelated file denials, remain supported. An optimized Nix loader with multiple
hardlinks needs a dedicated single-link copy outside write and deny paths in this configuration.
Otherwise `Prepare` fails closed naming the binary, loader and denied directory (`ErrLoaderRefused`).
A loader that is or leads through a `/proc` path (`config.ThroughProc`) is refused the same way before it is opened
(*amended 2026-10-16*, agent-contract.md R8a): opened in the launcher, `/proc/self/exe` is tego's
own executable. Compile refuses such a `PT_INTERP`; this catches a binary rewritten since.

*Amended 2026-10-16 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) D2, Stage B):* a table whose held opens need the open deputy (`gate.completion:
held` with an fs gate rule that can score to `allow` or above (*amended 2026-10-20*, ADR 0007), `RuleTable.NeedsOpenDeputy`) and whose domain handles
`EXECUTE` (an `exec:` section with an allow list) also holds tego's own binary, `/proc/self/exe` resolved at
Prepare, with `EXECUTE|READ_FILE` (entry kind `open deputy`), and its ELF loader for a dynamic build, so the child
stage can exec the deputy after `landlock_restrict_self`. The grant is the domain's, not the contract's: no exec rule
names it, and the agent's own exec of the binary is still the supervisor's to decide (supervisor R16b)
(`TestDeputyExecGrant`). Compile's printed table names it on the gate line, as the effective policy shows the other
runtime grants ("runtime exec grant: tego's own binary, for the deputy", `TestGateCompletionKey`). The harness hook's
grant ([ADR 0064](../adr/0064-harness-hook-exec-grant.md), *added 2026-10-25*) is another kind: an exec rule the
runtime adds to the table (`agent.WithHarnessHook`), so this builder grants the binary and its loader as it grants any
exec rule, entry kind `exec`, and the supervisor decides the vector; the binary or its loader under a write, ask or
`deny_read` entry gets no such rule (the provision is dropped), so the loader refusal above never fails a run for it.

**R5a — negative-write admission (ADR 0041 D1 (a)).** A nonempty built-in `RuleTable.DenyWrite` lies beneath a
write entry, where no ruleset can refuse a write, so this tier never holds it. By default (`fs.assurance`
best-effort) `Prepare` builds the plan as for any table and the supervisor refuses a modification that reaches a
target on its copied pathname (supervisor R15c), best effort: compile warns once per target and run_start's
`best_effort` lists `deny_write/default`. Under `fs.assurance: kernel` (`RuleTable.DenyWriteNeedsPlane`) a target
needs a kernel decision plane: without plane rows `Prepare` fails with `ErrNegativeWriteNeedsPlane`, naming the
first target and the fix, before building any ruleset, also when this plan is inherited by tier cgroup, and
selection refuses the run before launch (exit 125, `tier-unavailable`). Cgroup with a working `lsm`/`fmod_ret`
plane and bpflsm decide the targets in the kernel either way and retain writes outside them. Contracts with no
such targets are unaffected (`TestProtectedWritesRequirePlaneBeforeAnyRuleIsBuilt` and
`TestSelectProtectedWritesRequiresActualPlane` under `kernel`, `TestProtectedWritesBestEffortByDefault` and
`TestSelectProtectedWritesBestEffortByDefault` by default).


**R6 — per-port `CONNECT_TCP`/`BIND_TCP`, ABI ≥ 4 (corrected).** For every distinct TCP port named across
`net.allow`'s `host:port`/`cidr:port` entries (deduplicated by port number — Landlock's `LANDLOCK_RULE_NET_PORT`
rule is port-only and cannot see the host), one `landlock_add_rule` grants `CONNECT_TCP` for that port
(`struct landlock_net_port_attr{allowed_access, port}`, present since ABI 4/kernel 6.7 — not, as an earlier
draft of this spec stated, a no-port right; see Corrections C1). `BIND_TCP` is granted only on a port a `tcp://`
`net.listen` entry declares (amended 2026-10-05: `net.listen`, network-controls R2, supersedes "no contract field
declares a listen port"); port rights are per protocol, so a `udp://` entry grants `BIND_UDP` alone (R22) and a
`unix:` entry no port right. With no such entry (no `net.listen`, `listen: []`, or only `udp://`/`unix:` entries)
any in-domain `listen()`/`bind()` on a **classic TCP socket** fails `EACCES`. The port rule cannot see the
address, so a declared port is granted on every local address; the address is decided where `net.listen` is
present by the supervisor, which is then notified of every `bind` and `listen` (R11; supervisor `bind.go`,
`agent.MatchBind`). Landlock's net hooks dispatch on `sk_is_tcp()`/`sk_is_udp()` and skip every other protocol,
and with no `net.listen` the supervisor continues a `bind(2)` for Landlock to decide (R11c), so that denial reaches an
`IPPROTO_MPTCP` socket only because the filter refuses `socket(_, _, IPPROTO_MPTCP)` outright (E30).
*Amended 2026-11-01:* `BIND_TCP` decides an explicit `bind(2)` and nothing else. A `listen()` on an unbound socket
takes its port through the kernel's autobind, which never calls `security_socket_bind`, so no right withheld here
refused it: with no `net.listen` a run got a listener on `0.0.0.0:<ephemeral>` that took connections from outside the
run, with no line. The `listen` half of the sentence above is now the supervisor's: every `net:` section notifies
`listen` (R11c), and with no `net.listen` `handleListen` refuses a TCP `listen` whatever port the socket shows,
`EACCES`, one refused line, rule `unmatched`. It is not keyed on port zero: a connect in flight gives a socket a port
its failure takes back, between the supervisor's `getsockname` and its `listen`.
`net.allow` empty ⇒ no net rule at all, so **every** TCP connect fails `EACCES` at the Landlock layer for any
port. No `net:` section at all ⇒ no net right is handled (`handled_access_net` is 0), so Landlock refuses no
connect and no bind: SEMANTICS §1's "no `net:` — deny nothing", which the supervisor (every connect answered
`CONTINUE` and performed by the agent itself, supervisor R7) and `decide.Evaluate` (`allow`/`unmatched`) read off the
same contract bit. The scope (R7) is not a net right and stays handled: with no `net:` the agent's own connect is
still refused for an abstract name bound outside the run — a relay from the supervisor, which has no domain, would
escape it, which is why none is made (supervisor R7) — and that scope is the one kernel check stricter than "deny
nothing". `RESOLVE_UNIX` sits in the filesystem mask but is net:'s pathname-socket half (R21), so with no `net:` the
builder drops it from the handled mask and from every write entry's grant at every ABI (`newBuilder`,
`TestNoNetSectionHandlesNoUnixRight`), so the agent's own connect to a pathname socket outside a write entry
(`/run/user/<uid>/bus`, `/run/docker.sock`, an X11 socket) is allowed at every ABI, as the supervisor and
`Evaluate` allow it. The one destination such a contract still refuses, a `models[]` endpoint under `capture:
forwarder` (SEMANTICS §1), is refused by the supervisor alone (supervisor R7, which relays every IP connect then):
a port rule cannot name a host, and granting every port but the model's would refuse every other host on that port
too, so the builder still handles no net right. This grant is a **backstop**, not the primary path: the common
allowed connect never reaches Landlock's own verdict, because the supervisor performs the real `connect()` on a
`pidfd_getfd` duplicate from an **unrestricted** task (ARCHITECTURE §7 — Landlock evaluates only the calling task's
own domain), matching host and port itself; R6's grant instead catches a `connect(2)` that reaches the kernel from
*inside* the domain without going through that path (e.g. a notify-predicate gap, R11) — now refused unless its
port was actually declared, closing the coarse "any port" gap the earlier draft left open.

**R7 — scopes on ABI ≥ 6.** `handled_access_scope` includes `SCOPE_SIGNAL` and `SCOPE_ABSTRACT_UNIX_SOCKET`,
declared once globally at `landlock_create_ruleset`, no per-rule grant. Directional: confines the **agent**'s
signals/abstract-socket connects to its own domain/descendants; never restricts an un-landlocked ancestor
(the supervisor) from reaching the agent, so this never breaks the control channel (`pidfd_getfd`, `ptrace`,
`ADDFD`). Below ABI 6 (the 5.14, 6.1 and 6.8 rows of the support matrix) there is no signal scope, and without
more the tier-1 agent, sharing its launcher's uid, could `SIGKILL` the launcher (the
record ends with no `run_end`), `SIGSTOP` it (every notified syscall of the run then waits on a stopped supervisor) or
`SIGTERM` it (`run_end` reads as an operator's stop), and signal every other process of the user, with nothing
refusing or recording it. So below ABI 6 an enforcing run's filter notifies `kill`, `tkill`, `tgkill`,
`rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `fcntl` with `F_SETOWN`/`F_SETOWN_EX` (which aim a descriptor's SIGIO at
a process) and `ioctl` with `FIOSETOWN`/`SIOCSPGRP`, which set the same owner, and answers `pidfd_send_signal`
`ENOSYS`, whose descriptor target another thread could swap between a decision and the kernel's use (runtimes that
use it, Go's `os.Process`, probe it once and fall back to `kill(2)`). The supervisor decides each as the scope
would (supervisor R33). An observe run's filter has no such arm, and from ABI 6 the kernel's scope decides and the
arm is not installed. The signal scope does not cover a change to another process's resource limits or scheduling,
which no ABI's scope or hook governs: `prlimit64(launcher, RLIMIT_CPU, {1, 1})` had the kernel `SIGKILL` the
launcher inside an ABI-6 domain. So at every ABI an enforcing run's filter also carries the process-scope arm
(`procScopeTest`): `prlimit64` with a non-zero pid and a new limit, `sched_setparam`/`sched_setscheduler`/
`sched_setaffinity`/`sched_setattr` with a non-zero pid, and `setpriority`/`ioprio_set` unless they name the caller's
own process are notified, and the supervisor decides them against the run's cgroup (supervisor R35). An observe
run's filter has no such arm either.

**R8 — implicit denies via omission.** The run directory, contract file, `/sys/fs/cgroup`, `/sys/fs/bpf` are
held (`kindImplicitDeny`, `Access: 0`) purely for identity, never granted write/make/remove rights. Because
the write-side mask is always a handled right (R11), omission alone denies them — no special rule. `compile`
already guarantees the run directory lies outside every write dir (exit 125 [contradiction] on overlap), so no conflicting
broader grant exists to reconcile.

**R9 — seccomp filter shape.** Arch guard first: `seccomp_data.arch` against the build's native
`AUDIT_ARCH_*` (`0xC000003E` x86_64, `0xC00000B7` arm64), `ERRNO|ENOSYS` on mismatch. Then, x86_64 only, test
bit `0x40000000` of `nr` (the x32 personality bit) clear, `ERRNO|ENOSYS` if set — compiled out entirely on
arm64 (no x32 personality exists there), not merely skipped at runtime. Both checks precede every syscall-
number comparison, because a compat-ABI call renumbers `open`/`connect`/etc. entirely.

**R10 — unconditional `ENOSYS`.** `io_uring_setup`/`_enter`/`_register` (425/426/427, identical on both
arches), `openat2` (437, identical) and `open_by_handle_at` (304 on x86-64, 265 on arm64) return `-ENOSYS` with
**no** notification (*amended 2026-10-24, ADR 0069 D2:* and `uselib` (134, x86-64 only), which opens a file by a
pathname no open-family arm sees, so a held read could not be completed on it; arm64 has no such syscall): `io_uring` submits opens/connects/sends through a ring with no observable syscall;
`openat2`'s flags live in a `struct open_how` in user memory classic BPF cannot dereference; and
`open_by_handle_at` opens from a `struct file_handle`, so no path exists for the supervisor to record, whatever
the flags — a write-open through it, or any open under `record: full`, left no line in any tier. Linux 6.12 lets
an unprivileged caller use it for some handles; below that it takes `CAP_DAC_READ_SEARCH`, which a tier-2 agent
can reach through a set-uid binary (runtime-launch R4 skips `no_new_privs` there). `name_to_handle_at` opens
nothing and stays allowed. An observe run's record, which `drift` and learn mode read, is the case that needs the
promise that no open reaches the kernel through a syscall number the supervisor has no entry for, so the set
applies to observe runs too. `io_uring: true` in the contract is a no-op below tier 2 (SEMANTICS §6). One exception
(ADR 0018 (5), TIER3-PLAN T13): a contract that declares `io_uring: true`, run at tier cgroup where a decision plane
mode decides every submission in the kernel (`Run.IOUring`: the plane's `socket_create`, path and file hooks, and
`cgroup/connect_unix` on 6.7+ or the plane's unix hooks below), gets the filter without the three `io_uring_*` arms, which it then allows with no
notification (`TestFilterIOUringArm`, `TestPrepareAdmitsIOUringOnlyWithThePlane`); `openat2`, `open_by_handle_at` and
`clone3` stay ENOSYS.
`clone3` (435 on both arches) is in the set as well. Its flags are in a `struct clone_args` in user memory, and
`CLONE_INTO_CGROUP` is checked by the kernel with `inode_permission`, which Landlock does not hook, so an allowed
`clone3` let a process of the run start a child in any cgroup its uid may write — at tier 1 every leaf of
`user@<uid>.service`, a concurrent run's cgroup included — outside the run's `pids.max`, `memory.max` and kill,
alive past `run_end` (it kept the run's Landlock domain and filter). glibc (2.34+) and Go fall back to `clone(2)`,
which has no cgroup argument, as they do under Docker's default profile. The launcher's own `clone3` into the run's
cgroup comes before the filter is installed and is unaffected.
*Amended 2026-10-17 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) Stage B):* a run whose held opens the open deputy completes (`gate.completion: held` with an fs gate rule that can score
to `allow` or above (*amended 2026-10-20*, ADR 0007), `RuleTable.NeedsOpenDeputy`) also answers `landlock_create_ruleset`, `landlock_add_rule` and
`landlock_restrict_self` (444/445/446, identical on both arches) `ENOSYS` with no notification
(`filterOpts.heldOpens`). The deputy makes every held open in the domain the child stage made; a process of the run
that made a domain of its own beneath it (`landlock_restrict_self` is allowed under no_new_privs) was held only to the
run's domain for those opens, so `setpriv --landlock-access fs:read-file` with read rules on `/usr`, `/lib` and `/etc`
alone had a worktree file's bytes delivered under `held` that its own domain refused under `copied`. With the three
calls answered as on a kernel without Landlock, every process of the run is in exactly the deputy's domain. An agent
that sandboxes its tools with Landlock finds it unavailable under `held` (a library's version probe reads `ENOSYS` as a
kernel without it), and so does a tego run inside the run; compile's printed table says so on the gate line
(`TestHeldCompletionRefusesNestedLandlockDomains`, `TestGateCompletionKey`). The arm is the contract's, assembled by
Prepare before the deputy starts, so a run whose deputy did not start (the degrade: its open cells best effort) keeps
it.
Under `net.assurance: kernel` (tiers cgroup and bpflsm only; tier 1 refuses the setting, `internal/runtime`
`validateNetworkRequest`) the filter also answers `recvmsg`, `recvmmsg`, `pidfd_getfd`, `listen`, `accept` and
`accept4` (47/299/438/50/43/288 on x86-64, 212/243/438/201/202/242 on arm64; `archTable.ClientDeny`) `-ENOSYS` with
no notification, ahead of every notify arm (amended 2026-10-05): each imports a socket from another process or
creates a listener the kernel destination hooks never decided, and `Handle.NetworkGuarantees` reports
`SocketImportsDenied`, and `ListenersDenied` with no listener declared, from this arm. A nonempty `net.listen`
leaves `listen`, `accept` and `accept4` out of it. `TestStrictClientFilterClosesSocketImportsAndListeners`, on
the kernel `TestStrictClientFilterOnRealKernel`, and per name against x/sys `TestFilterNumbersAreTheKernels`.

**R11 — notify list and CONTINUE-able vs errno returns.** Three dispositions: `ALLOW` (default); `ERRNO`
(R10, unconditional); `USER_NOTIF` for: `connect` (unconditional — no discriminating syscall arg); `sendto`
when `args[4] != 0` (direct scalar test, R12), or, in a run that decides datagrams, when its flags carry `MSG_MORE`
(R11d); `sendmsg`/`sendmmsg` **unconditionally** (msg_name is inside a
struct classic BPF cannot dereference — the "known datagram fd, msg_name set" filtering from ARCHITECTURE §7
happens in the supervisor after `ID_VALID`, not in this filter); `execve`/`execveat`; `open`/`openat`/`creat`
gated by the write-flag test (R12) or unconditional under `record: full` (R16); `unlink*`/`rename*`/`mkdir*`/
`symlink*`/`link*`/`mknod*` (x86-64's `mknod` 133 and `mknodat` 259, arm64's `mknodat` 33; a mknod
beneath a write entry made a regular file, FIFO or socket inode with no line and past `deny_write`) and x86-64's `rmdir` (84; arm64 removes a directory through `unlinkat` alone)
unconditionally (inherently mutating — `rmdir` was missing until 2026-09-22, so glibc's `rmdir(3)`, Python's
`os.rmdir` and coreutils' `rmdir` deleted a directory with no line, which Landlock's `REMOVE_DIR` still decided);
`truncate(2)` from ABI 3 (76 on x86-64, 45 on arm64; below ABI 3 R2's arm refuses it instead), which Landlock's
`TRUNCATE` decides and which left no line in any tier; under `record: full`, and under an `fs.write` gate at every
record level, the mode-change family `chmod`
(x86-64's 90), `fchmod`, `fchmodat` and `fchmodat2` (91/268/452 on x86-64, 52/53/452 on arm64), which no fs rule below
tier 3 refuses and which left no line either (supervisor R17, `CAPABILITIES` "record reads, mmap, chmod"); the gate
scores one as an `fs.write` and refuses it above its threshold, so it keeps the notification under `summary`/`off`
as gate.md's enabled action kinds do (amended 2026-10-05; `TestWriteGateNotifiesTheChmodFamilyUnderEveryRecordLevel`, on the kernel
`TestWriteGateNotifiesChmodOnRealKernel`, end to end with the supervisor `TestWriteGateNotifiesChmod`, golden dumps
`filter_*_gate_write.txt`); under an `fs.write` gate only, at every record level, the attribute families beside it
(`archTable.Attr`): `setxattr`, `lsetxattr`, `fsetxattr`, `removexattr`, `lremovexattr`, `fremovexattr` (188/189/190/
197/198/199 on x86-64, 5/6/7/14/15/16 on arm64), 6.13's `setxattrat` and `removexattrat` (463/466 on both), and
`chown`, `fchown`, `lchown`, `fchownat` (92/93/94/260 on x86-64; arm64 has `fchownat` 54 and `fchown` 55), which the
supervisor scores as writes too (supervisor R17): a POSIX ACL is the xattr `system.posix_acl_access` and setting one
rewrites the mode bits as `chmod` does, so a gate that refused `chmod 755 ../outside/f` let `setfacl` make the same
change unscored, and a `chown` hands the group bits to another group (amended 2026-10-16, ADR
0041 Step 2; `TestWriteGateNotifiesTheAttributeFamilies`, end to end `TestWriteGateNotifiesXattrAndChown`).
`record: full` does not notify them (its promise is reads, mmap and chmod), and timestamps (`utimensat` and the
older forms) are notified under no option: they change no permission, and `tar x` sets one per file;
`mount`, `umount2`, `pivot_root` and `move_mount`
unconditionally — the four entry points this domain refuses (`sb_mount`, `sb_umount`, `sb_pivotroot`,
`move_mount` in `security/landlock/fs.c`), which the supervisor answers with the domain's own `-EPERM` and records
as `refused` / `gap what=enforce why=landlock-topology` (SEMANTICS §10; supervisor R31); `add_key`, `request_key`
and `keyctl` **unconditionally** (248/249/250 on x86-64, 217/218/219 on arm64) — the kernel keyring no fs, net or
exec rule can see and no tier's hooks reach, which the supervisor refuses with `-EPERM` and records `refused
reason=read-denied rule=keyring` unless the contract declares `keyring: true`, and otherwise continues and records
as `gap what=record why=keyring-<syscall>` (SEMANTICS §1, supervisor R32); System V IPC,
**unconditionally**: `shmget`/`shmat`/`shmctl`/`semget`/`semop`/`semctl`/`msgget`/`msgsnd`/
`msgrcv`/`msgctl`/`semtimedop` (29/30/31/64/65/66/68/69/70/71/220 on x86-64,
194/196/195/190/193/191/186/189/188/187/ 192 on arm64), which the supervisor refuses with `-EPERM` and records
`refused reason=read-denied rule=sysv-ipc` unless the contract declares `ipc: true`, and otherwise continues and
records as `gap what=record why=sysv-ipc-<syscall>` (SEMANTICS §1, supervisor R34); in every filter, the
namespace arm: `unshare` and `clone` (272/56 on x86-64, 97/220 on arm64) when `args[0]` carries `CLONE_NEWNS` or
`CLONE_NEWUSER`, and every `setns` (308 on x86-64, 268 on arm64), which the supervisor refuses where the run
enforces and records as `landlock-topology` (enforce-cgroup-observe E24; supervisor R1); while the contract has a
`net.listen` list, empty or not, `bind` and `listen` (49/50 on x86-64, 200/201 on arm64) **unconditionally**,
which the supervisor decides by the declared listeners (supervisor `bind.go`, network-controls R2; amended
2026-10-05); under `net.ingress`, `setsockopt` (54 on x86-64, 208 on arm64) at level `IPPROTO_IP` with
`IP_BIND_ADDRESS_NO_PORT` (24) is **refused with `EPERM`** in the filter, since that option defers port allocation
past the post-bind hook that attributes a socket to its verified listener (`noPortBindTest`;
`TestListenerAdmissionAndNoPortBindFilterBothArchitectures`); and `ioctl` is **refused
with `EPERM`** when its request is `TIOCSTI` or `TIOCLINUX`, which is the one place the filter decides rather than
records at every tier. The filter's contents depend on the tier: at tiers `cgroup` and `bpflsm` only, the root-tier
arm answers `bpf`, `init_module`, `finit_module`, `delete_module`, `kexec_load` and `kexec_file_load` (321/175/313/
176/246/320 on x86-64, 280/105/273/106/104/294 on arm64) with `EPERM` whatever the contract says, with no ledger
line, like R10's arms (ADR 0033 (3)); tier 1 does not install it. A build with `-tags tegotesthooks` can leave
named syscalls out of both the notify arm and this one (`TEGO_TEST_FILTER_OMIT`, the `filterTestOmit` seam), so
that a root test reaches what these arms answer first in a product run, the decision plane's `bpf` and
`key_permission` hooks (enforce-plane §2.20). In a product build `filterTestOmit` is a function that always answers
false, so no syscall is left out, whatever the environment says
(`TestFilterTestOmitLeavesOnlyTheNamedArmsOut`, `TestAProductBuildLeavesNothingOutOfTheFilter`).

That exception is deliberate. Both ioctls write into the controlling terminal's input queue, and an agent
inherits the launcher's stdio, which on an interactive run is the user's own terminal — so either one lets
the agent write a command the user's shell then runs, as the user, outside every boundary the run installs.
It is CVE-2017-5226 against bubblewrap, and why flatpak, firejail and snap all refuse them. Landlock has no
view of `ioctl` and the supervisor's filesystem answers are advisory, so this filter is tier 1's only
opportunity. Deciding here is sound where deciding on a path is not, because the request number is a scalar
in `args[1]`: classic BPF compares it exactly, and there is no memory for the target to change afterwards
(R11's reason for notifying rather than deciding does not apply). `EPERM` rather than `ENOSYS` because
`ioctl` plainly exists. Linux 6.2's `dev.tty.legacy_tiocsti` sysctl disables `TIOCSTI` kernel-wide and
defaults to off, but the floor here is 5.14, the sysctl is writable, and it does not cover `TIOCLINUX`. `link`/`linkat` are in that set for the reason the
rest are: a hard link gives existing content a second name, so a record that carries `symlink` but not `link`
would show one way of naming a file twice and hide the other. Landlock still makes the decision — `MAKE_REG`
on the destination directory, plus `REFER` on both when they differ (ABI 2) — and the supervisor answers
`CONTINUE` as it does for every other mutating entry. *Amended 2026-10-17:* the supervisor's line predicts exactly that decision (supervisor.md R17): asked of the directories, never of the
file, so a file-level write entry (masked to file rights here, R3) gets no second name elsewhere, and with the no-gain
rule over the rights this builder grants, an exec grant's `EXECUTE` included. Post-notify, the **supervisor's reply**, not the filter,
decides outcome: connects get the real result of a `pidfd_getfd`-duplicate connect or `error=EACCES` (never
`CONTINUE` for a connect); everything else recorded is answered `CONTINUE` — enforcement of those, where it
exists, is Landlock's own hook on the now-continued syscall, independent of the supervisor.

**R11a — the `memfd_create` arm.** `memfd_create` (319 on x86-64, 279 on arm64) is decided in the filter
by one of two arms, both of which refuse the *creation* of a memfd the kernel would exec. Like the `ioctl` arm each
decides in the filter rather than recording, and for the same reason: the syscall number and the flags (`args[1]`)
are scalars in registers, immutable once the syscall traps, so there is no memory for the target to change
afterwards and the closure is race-free. It exists because an anonymous image — an ELF written into a memfd — runs
an exec no `exec.allow` entry names: Landlock's `file_open` allows a memfd's `SB_NOUSER` superblock outright and
tier 2's `FAN_OPEN_EXEC_PERM` sees no open a `fexecve` makes, so deciding it after the fact from the descriptor the
supervisor's walk reads loses to a descriptor-table race (supervisor R16b, SEMANTICS §4).

- **Sealing arm, a kernel that honours `MFD_NOEXEC_SEAL`** (6.3 and later, and a kernel that backports the flag, as
  RHEL 9.8's 5.14 does; `MemfdNoexecSealSupported`, a probe that creates one memfd with the flag, decides, never the
  version): refused with **`EACCES`** unless the flags set `MFD_NOEXEC_SEAL` (`0x8`) and leave `MFD_HUGETLB` (`0x4`)
  clear, allowed otherwise. `MFD_NOEXEC_SEAL` clears and seals a shmem memfd's execute bits, so a memfd made with it cannot be
  exec'd, while a data memfd that sets it (an ordinary workload's shared memory) is created normally. A hugetlb memfd
  is refused even with the flag: `memfd_create` sets `F_SEAL_EXEC` on it, but only `shmem_setattr` enforces that
  seal, and `hugetlbfs_setattr` lets an `fchmod` give the file its execute bits back (verified on 6.17: `fchmod
  0755` succeeds on a sealed hugetlb memfd and fails `EPERM` on a sealed shmem one), so the arm tests both flags,
  not the seal flag alone.
- **Refusing arm, a kernel without the flag** (upstream before 6.3 and a distribution kernel that did not backport
  it, such as Amazon Linux 2023's 6.1, verified in a guest): every `memfd_create` is refused with **`ENOSYS`**,
  whatever its flags. There `MFD_NOEXEC_SEAL` does not exist (`sanitize_flags` answers `EINVAL`), no flag separates
  an executable memfd from a data one, and any memfd can be written with an ELF and run, so creating none is the only closure at creation — as
  race-free as the sealing arm, since it decides on the syscall number. `ENOSYS` rather than `EACCES` because it is
  what a kernel without `memfd_create` (before 3.17) answers: a runtime that uses a memfd for shared memory takes its
  pre-memfd path, a file in `/dev/shm` or an `O_TMPFILE`, which the ruleset and `exec.allow` govern like any other
  file, rather than failing on an errno it does not expect (the reasoning behind R10's `ENOSYS`). What this costs
  an operator on a kernel without the flag is a memfd for anything, data included; `exec: {anonymous: true}` gets it
  back and gives up the closure (GAPS C30). Without this arm the vector would rest on the supervisor's best-effort
  walk alone.

An arm is installed only when the run restricts exec (`Contract.Exec != nil`, so an anonymous image is never a
granted exec) and the contract did not opt out with `exec: {anonymous: true}`, which drops the arm and makes the
supervisor allow an anonymous image, still recorded `fileless`. That opt-out is on the run's capability line as well
as in its `contract_hash`: the handle reports `exec.deny` `false`, because with no arm the agent can copy any binary
it can read into a memfd and run it, so `exec.allow` no longer bounds what runs (`record-ledger.md` §2.2). Tier 2
reports it too: its `Handle.Capabilities` clears `exec.deny` wherever the inherited tier-1 handle's row withholds it,
with or without a decision plane, whose exec row allows anonymous images for such a run
(`TestExecDenyFollowsTheInheritedRuleset`).
Tier 2 inherits the arm with the rest of the filter (R13). The refusal leaves no ledger line, like the `ioctl` and
MPTCP arms: nothing ran, and the agent sees the errno. At tiers 2 and 3, a run a plane mode with step C decides
(`Run.PlaneMaps`: its plane rows ride on the run, and the plane's hooks include `mmap_file` and `file_mprotect`, which
doctor's probe saw refuse) gets no refusing arm on a kernel without the flag: the plane's `bprm_check` and
`mmap_file` refuse an anonymous image's exec and its `PROT_EXEC` map race-free, so a data memfd is created there
(enforce-plane R27, §2.14). The sealing arm stays where the kernel has the flag
(`TestMemfdArmDroppedWhereThePlaneMaps`).

**R11b — the source-route arm (ADR 0041 D6).** *Added 2026-10-05.* When the contract's
gate scores `net` actions (`gate.Net`), `setsockopt` (54 on x86-64, 208 on arm64) is **refused with `EPERM`** when
it would give a socket a source route: level `SOL_IP` (0) with `IP_OPTIONS` (4), and level `SOL_IPV6` (41) with
`IPV6_RTHDR` (57), `IPV6_2292RTHDR` (5) or `IPV6_2292PKTOPTIONS` (6). Every other option is allowed. Under a net
gate the supervisor performs an admitted IP connect, Fast-Open send or datagram itself, on a duplicate of the agent's
socket, with the address the gate scored (supervisor R9, R12, R13b), and reads the socket's options first: a socket
carrying an LSRR/SSRR option or a routing header is refused `relay-source-routed`, because its first hop is an
address the gate never scored. That read is a snapshot of a socket every thread of the agent shares, so a sibling's
`setsockopt` between the read and the relayed call put a route on a socket the read had found clean (an
unprivileged task may set both). This arm refuses the `setsockopt` itself. Level and option are scalars in
`args[1]` and `args[2]`, so the decision is race-free, as the ioctl and MPTCP arms' are; both are `int`s, so the low
32 bits are what the kernel reads. The refusal leaves no ledger line, like theirs. A gated run has no `io_uring`
(a gate requires `io_uring` disabled), so the syscall is the only way to set an option. What the supervisor's read
still decides is a socket that carried a route before the filter applied: one inherited from the launcher, or
received over a unix socket. A process outside the run that holds the same socket is not under this filter and can
still set a route on it at any time; that is a disclosed residual (gate.md R4), not a refusal. IPv6's
`IPV6_2292RTHDR` only asks Linux to receive routing headers, but the arm refuses it with the others rather than
rest on that reading. Tier 2 and 3 inherit the arm with the rest of the filter (R13).
(`TestNetGateFilterRefusesSourceRouteOptions` on both architectures' register layouts;
`TestFilterRefusesSourceRouteOptionsOnKernel` on the real kernel, where both options are accepted without the arm.)

**R11d — the pending-frame arms (supervisor R13).** *Added 2026-10-20 (ADR 0008's design note).* In a run that decides datagrams (`agent.RuleTable.DecidesDatagrams`: a `net:` section, a guarded
`models[]` endpoint or a net gate; `filterOpts.frames`) the filter notifies every syscall that can leave a UDP frame
pending on a socket, so the supervisor can decide it on the socket's own kind: a `sendto` with no address whose flags,
`args[3]`, carry `MSG_MORE` (`0x8000`; an addressed one is notified anyway, and `sendmsg` and `sendmmsg` always are);
`setsockopt` (54 on x86-64, 208 on arm64) at level `SOL_UDP` (17) or `SOL_UDPLITE` (136) with `UDP_CORK` (1); and every
`sendfile` (40 on x86-64, 71 on arm64) and `splice` (275, 76). The supervisor refuses `MSG_MORE` on, and a `sendfile`
or `splice` into, a socket that can hold a frame, and refuses every such `setsockopt`, each with a `datagram-corked`
line (supervisor R1, R13); everything else it continues. The flags, level and option are `int`s, whose low 32 bits are
what the kernel reads, so the arms test those, race-free; the descriptor's kind is read by the supervisor on its
duplicate, which a sibling that swaps the descriptor between that read and the kernel's use can race (supervisor R13's
residual). The arms are notifications, not errno returns, so a refusal has its line and an observe run's supervisor
continues them as it continues everything (supervisor R30); the filter and the supervisor read the one predicate, so
a run never has the one without the other. An observe run's filter (`BuildFilter`, built by `enforce.Observe`)
carries them too where its contract decides datagrams, though it leaves out the other arms that refuse rather than
notify (R2's truncation rows, memfd, the signal and process scopes, the root tier): its supervisor applies the same
pending-frame decisions, so its record holds a line for each operation the enforcing run would refuse
`datagram-corked`, the unaddressed ones included, and the kernel then performs each (amended 2026-10-20; before, the observe filter had no such arm, and its record held only the addressed sends with
`MSG_MORE`, under-reporting what enforcement would refuse). That line is never a `refused` one, since nothing was
refused (supervisor R30): a send with `MSG_MORE` and a copy into a socket that can hold a frame are `net` lines stamped
`observed`, rule `datagram-corked`; a cork, and a copy whose output descriptor could not be read, are `gap
what=record why=<rule>-<syscall>` (`datagram-corked-setsockopt`, `fd-unreadable-sendfile`, ...), once per binary,
syscall and rule (amended 2026-10-20); for a non-dumpable process, whose
binary the same ptrace check hides, once per process, naming no binary and carrying its pid (supervisor R31; amended
2026-10-20). The cost is a notification, a `pidfd_getfd` and a socket read for each
call the arms notify that is not refused: a TCP send carrying `MSG_MORE`, a `sendfile` that copies a file (Python's
`shutil` copies with it) or a `splice`. A workload that sends with `MSG_MORE` on TCP pays it on every such send (not
measured); one that copies files with `sendfile` pays it once per call, which covers a whole file. A copy whose output
descriptor the supervisor cannot read is refused, not continued, since it may be into a socket that holds frames: at
tier 1 `pidfd_getfd` refuses every descriptor of a process that made itself non-dumpable (`PR_SET_DUMPABLE` 0, as
`ssh-agent` does), so in a run that decides datagrams such a process's every `sendfile` and `splice` fails `EACCES`,
a file-to-file copy included, recorded `refused`, op `sendfile` or `splice`, rule `fd-unreadable` (supervisor R13,
the failure table; amended 2026-10-20). A run that decides no datagrams carries none of them. Tier 2 and 3 inherit them with the rest of the filter (R13). (`TestFilterNotifiesWhatCouldStartAPendingFrame` on both architectures' register layouts;
`TestEveryNotifiedSyscallHasAHandler`; end to end `TestIntegrationAskUDPPendingFrame`.)

**R11c — `bind(2)` and `listen(2)` under a `net:` section (supervisor R11a).** *Added 2026-10-16.* Under a `net:` section with no listener policy (`net.listen` absent; one present notifies `bind` and `listen`
for its own decisions), `bind` (49 on x86-64, 200 on arm64) and `listen` (50, 201) are **notified**. The supervisor
records the socket a pathname unix bind names, by its sockfs inode and `SO_COOKIE`, and answers `CONTINUE` with no line,
so the kernel — Landlock's `MAKE_SOCK` on the parent, `BIND_TCP`/`BIND_UDP` for an IP socket — decides the bind exactly
as when it was not notified; that record is what the implicit admit of a socket under a write entry is held to
(supervisor R11a). *Amended 2026-11-01:* `listen` is notified for R6: the supervisor refuses a TCP `listen` and makes
any other on a duplicate of the socket, since the filter cannot tell the two apart and a continued unix `listen` is a
descriptor number a sibling's `dup2` points at a TCP socket. The cost is at tier 1: a non-dumpable process's `listen`
fails closed, `fd-unreadable` (GAPS C44). In the unix-only state of a contract with no `net:` section (ADR 0070) `bind`
alone is notified, for the same record. With no `net:` section and none of that state, nothing is decided about a unix
socket and the arm is not installed. Both calls are rare next to the notified opens and connects, so the arm costs a run
nothing measurable; tier 2 and 3 inherit it with the rest of the filter (R13). (`TestPrepareNotifiesListenUnderANetSection`;
`TestListenerAdmissionAndNoPortBindFilterBothArchitectures` on both architectures' register layouts;
`TestUnixForeign` and `TestIntegrationListenerAdmission` at tier landlock on the real kernel.)

**R12 — write-flag test, exact offsets.** `seccomp_data`: `nr`@0(4B), `arch`@4(4B), `instruction_pointer`@8(8B),
`args[0..5]`@16,24,32,40,48,56 (8B each; only the low 32 bits are loaded for an `int` argument on a
little-endian kernel). `open(filename,flags,mode)`: `BPF_JSET` on `args[1]` (offset 24) against `0x243`
(`O_WRONLY 0x1|O_RDWR 0x2|O_CREAT 0x40|O_TRUNC 0x200`). `openat(dfd,filename,flags,mode)`: same mask on
`args[2]` (offset 32). `creat`: no test, always notified (implies `O_WRONLY|O_CREAT|O_TRUNC`). `O_TMPFILE`
(`0x410000`) requires `O_WRONLY`/`O_RDWR` to be linkable, already caught by `0x243`.

**R13 — `NEW_LISTENER`, no `TSYNC`.** Installed with `SECCOMP_FILTER_FLAG_NEW_LISTENER` only — mutually
exclusive with `TSYNC` (`EINVAL` unless `TSYNC_ESRCH`); the child installs on one locked OS thread that
`execve`s immediately, so no second thread needs syncing (ARCHITECTURE §5).

**R14 — datagram best-effort.** Connected-socket sends are decided at `connect` time (race-free, R6/R9);
unconnected `sendto`/`sendmsg`/`sendmmsg` are read under `ID_VALID` and matched: a destination the policy refuses
is refused with `EACCES` and nothing leaves, and an admitted one is `CONTINUE`d — TOCTOU-limited by design, since
the kernel reads the address again, stated as a capability-matrix row, race-free only in tier 2
(`cgroup/sendmsg`) (supervisor R13b). *Amended 2026-10-16:* every such send was
`CONTINUE`d regardless of match, so a refused datagram left under a refused line; `net.dns.mode: off` did not stop
a lookup sent from an unconnected socket. On ABI ≥ 10 this is layered with an in-kernel per-port backstop (R22) — the supervisor's
decision is still the primary, race-free-for-connect path; the Landlock port rule only catches sends that slip
past the notify predicate, exactly as R6 does for TCP.

**R15 — order: seccomp first, Landlock second.** The filter evaluates before the syscall's implementation
runs; a `CONTINUE`d or never-notified syscall then proceeds into the kernel where Landlock's hooks
(`file_open`, `path_unlink`, `path_rename`, `path_mkdir`, `path_symlink`, …) make the real decision
independent of what the supervisor recorded. This is why write-opens/deletes/renames/mkdirs/symlinks are
*recorded* by the seccomp pair but *enforced* by Landlock (the supervisor always replies `CONTINUE` for
these). Connects are the exception: the supervisor's reply **is** the result for the common path; R6/R22's
Landlock port rules are the fallback for whatever bypasses that path.

**R16 — `record: full` widens the predicate.** `rt.Record == agent.RecordFull` ⇒ `Prepare` builds a filter
variant with the write-flag test removed from `open`/`openat`/`creat`, so every open — read or write —
notifies (the filter cannot see the path, only flags; per-path watch/aggregation decisions need the
supervisor to see every open). Under `summary`/`off`, read-opens never leave the kernel — no notification, no
event (ARCHITECTURE §8). *Amended 2026-10-24 (ADR 0069 D2):* a table whose run holds its reads
(`RuleTable.ReadsHeld`: `fs.reads: auto` with a `deny_read` target inside a write entry, or `fs.reads: held`) gets the
same every-open arm under any record mode, through `filterOpts` as `fs.ask_read`'s does (`askRead`), and the
held-completion arm (R10's `landlock_*` `ENOSYS`, ADR 0041 D2) with the deputy's runtime exec grant: the supervisor
completes every read-capable open through the open deputy and refuses one on the object it reached, so a nested
`deny_read` R4 cannot compile holds at this tier. It writes no line for an allowed held read unless the record mode
keeps reads; R4's `unenforced` marker, and the I5 cross-check on it, are unchanged. *Amended 2026-10-25 (ADR 0077):*
`reason.reads: on` gets the same every-open arm at tier landlock (`RuleTable.ReasonReadsNotified`) where nothing else
notifies reads, and nothing else of held reads': the supervisor continues each read open, quietly when allowed, and one
the ruleset refuses under `deny_read` is one refused `read-denied` line with `mechanism: landlock`. The default, `auto`,
is ADR 0077's measured off, under which the filter is the one built before the key existed, byte for byte
(`TestReasonReadsNotifyEveryOpen`).

**R17 — refused vs recorded** (summary):

| Action | Refused by | Recorded by |
|---|---|---|
| write/create/remove outside grant | Landlock `EACCES` | seccomp notify + `CONTINUE` (advisory) |
| exec outside grant at a later binfmt stage (a `#!` interpreter or `PT_INTERP` loader the continued exec needs) | Landlock `EACCES` on the failing binfmt stage | seccomp notify on `execve`/`execveat` (fires regardless of the later verdict) |
| creation of a memfd the kernel would exec (`memfd_create` without `MFD_NOEXEC_SEAL`, or with `MFD_HUGETLB`; every `memfd_create` on a kernel without the flag) | filter at creation, race-free (R11a): `-EACCES` from the sealing arm (a kernel that honours the flag: ≥ 6.3, or a backport such as RHEL 9.8's 5.14), `-ENOSYS` from the refusing arm (a kernel without it); exec restricted, not opted out of via `exec.anonymous` | nothing: nothing ran (like the `ioctl`/MPTCP arms) |
| exec of an anonymous image that exists anyway (an fd over `SCM_RIGHTS` or inherited at launch, an unlinked file), by descriptor or any pathname reaching it | supervisor `-EACCES` (Landlock's `file_open` allows a memfd's `SB_NOUSER` superblock outright, SEMANTICS §4) — best-effort: any thread/`CLONE_FILES` child can swap the descriptor, any process writing the path can swap a symlink, after the decision | same notification, `rule: exec-anon`, `fileless: true`; allowed + recorded `fileless` under `exec.anonymous: true` |
| exec of a binary no entry grants, by any spelling | supervisor `-EACCES` (or the lookup's `ENOENT`) before Landlock sees it (supervisor R16b) | same notification, `refused`, `exec-not-allowed` |
| exec via a directly-invoked loader | supervisor `-EACCES`: the loader is granted for `PT_INTERP`, not as an exec of its own (SEMANTICS §4) | the loader's own `execve` notifies |
| `PROT_EXEC` mmap of a readable file | not refused in tiers 1–2 (Landlock has no `mmap_file` hook); tier 3 `mmap_file` refuses (SEMANTICS §4) | nothing: the mapped code makes no exec |
| TCP connect, undeclared host or port | supervisor `-EACCES` (host); Landlock `EACCES` if a leaked connect's port isn't declared (R6) | same notification |
| TCP connect, `net.allow` empty | Landlock `EACCES` (R6, grant omitted) | notify still fires; supervisor agrees |
| UDP send | supervisor `-EACCES` for an unconnected send to a destination the policy refuses (R14, supervisor R13b); an admitted one is continued, and the ABI ≥ 10 in-kernel port backstop refuses an undeclared port that a sibling's rewrite slips through (R22) | notify; refused, or `CONTINUE` with the best-effort caveat |
| `unix:` connect, ABI < 9 | supervisor only (no Landlock rule exists, R21), on the socket the path resolves to, as the task (supervisor R11) | notify on `connect`/`sendto`/`sendmsg` |
| `unix:` connect, ABI ≥ 9 | supervisor primarily, as above; Landlock backstop on a bypass (R21) | same |
| `deny_read` hit | Landlock `EACCES` (R3) | not recorded under `summary`/`off` unless the filter notifies reads (`reason.reads: on`, held reads, `fs.ask_read`, a read gate: then one refused line, `mechanism: landlock`, R16, ADR 0077); individual event under `full` (R16), with `mechanism: landlock` |
| mount/pivot_root/umount/remount | Landlock `EPERM` (any FS grant implies this, §6) | not directly observed by this component — §11 |

**R18 — the child stage's `sys.RestrictSelf` flag-then-fallback**, not probe-then-decide: trying the flag
directly against the already-built ruleset is cheaper than a second ABI probe and cannot disagree with what the
ruleset targets. It is the one `landlock_restrict_self` wrapper in the tree (`internal/platform/sys`, tested by
`TestRestrictSelfFallbackAndNoNewPrivs`); this package applies nothing. The fallback is for `NO_NEW_PRIVS` alone: a `LOG_*` flag the machine opted into (§4) is dropped before the call when
the ABI does not know it, never retried away after an `EINVAL`, so an audit flag the kernel knows is either
applied or fails the stage.

**R19 — `Capabilities()` reads the stored ABI, once.** `Select` probes the ABI (R1) and threads it into the
concrete `*Backend`; `Capabilities()` is a pure, syscall-free read of that field — "no probing" (§4) means no
*new* syscall per call, not an ABI-blind report. Reported `net`: `"none"` below ABI 4 (E4); `"tcp: declared
ports (landlock backstop) + host (supervisor)"` at 4–8; append unix at ABI ≥ 9 (R21) and udp at ABI ≥ 10
(R22). Resolves the tension between the interface's "static row" framing and E4's ABI-conditioned report. The
`net.unix_abstract_scope` row is provided at ABI ≥ 6, where every ruleset carries R7's abstract-socket scope, and
by nothing below it (agent-contract R19).

**R20 — no audit-quiet flags.** `landlock_add_rule`'s `flags` argument is unconditionally `0` at every ABI —
audit-quietness is a kernel-side logging property, never a rule-matching one. `LANDLOCK_ADD_RULE_QUIET` (ABI 10,
Linux 7.2) would mute the audit records of refusals under a rule, which are what the `landlock.audit` opt-in (§4)
exists to record, so no rule sets it. `landlock_ruleset_attr`'s `quiet_*` masks (the same ABI) stay 0 for the same
reason, and a kernel below ABI 10 refuses a non-zero one with `E2BIG` (`TestRulesetHandlesNoQuietMask`,
`TestLandlockCreateRulesetTail`). This rule governs `landlock_add_rule` and those masks only; `landlock_restrict_self`'s
`LOG_*` flags are §4's and R18's.

**R21 — `unix:` `net.allow` entries** (under a `net:` section; with none, no unix right is handled, R6)**.** Below ABI 9, Landlock has no AF_UNIX restriction of any kind
(`SCOPE_ABSTRACT_UNIX_SOCKET`, R7, confines the agent's own *use* of abstract sockets — not a per-path/name
grant; `RESOLVE_UNIX` doesn't exist before ABI 9): a declared entry is enforced **entirely** by the
seccomp-notify + supervisor path (R11), parallel to TCP host matching — the supervisor matches the name under
`ID_VALID` against the declared path or abstract bytes, then the socket that name resolves to as the task, and
makes the connect with the task's credentials (supervisor R11). The relay has no Landlock domain, so at ABI ≥ 9
its decision on the resolved socket is what stands in for this backstop on a relayed connect. At ABI ≥ 9, `Prepare` additionally opens
an `O_PATH` fd per pathname entry (dedup by `(st_dev, st_ino)`, R3/E7) and adds one `RESOLVE_UNIX`-class rule
per entry as a backstop, mirroring R6; abstract entries carry no fd. Required by SEMANTICS §5 and
CAPABILITIES.md's "unix sockets" row — ABI 9+ `unix:` entries must not stay seccomp-only. Every write entry also
carries `RESOLVE_UNIX` at ABI ≥ 9 (the write mask): a name-level backstop, wider than the supervisor's decision,
which admits a socket under a write entry only when the run bound it (supervisor R11a); Landlock cannot tell which
process bound a socket, so it backs only the run's own datagram sends, which the supervisor decides first.

**R22 — UDP in-kernel port backstop, ABI ≥ 10.** Layered onto R14: one additional Landlock net-port rule per
distinct declared UDP port, mirroring R6. Below ABI 10 this set is empty and R14 is unchanged. Required by
SEMANTICS §5 and CAPABILITIES.md's "UDP by port in-kernel: Landlock ABI ≥ 10 only" row. `BIND_UDP` is handled
with `CONNECT_SEND_UDP` and, whenever the contract has a host/cidr entry, granted on port 0 alone, the ephemeral
range: a UDP client that binds before it sends (`net.ListenUDP(":0")`, a QUIC or HTTP/3 stack) works, and a bind
to a fixed UDP port fails `EACCES`, as a TCP bind does (R6), unless a `udp://` `net.listen` entry declares it,
which grants `BIND_UDP` on that port (amended 2026-10-05). An explicit `net.listen` replaces the port-0 grant:
ephemeral allocation then needs a port-0 declaration (network-controls R2). With no `net.listen` the supervisor
continues a `bind(2)` (R11c), so that refusal is Landlock's alone and unrecorded; with one, R11 notifies `bind` and the
supervisor decides and records it.

**Changes.**
- 2026-11-01, R6, R11c, R22: `listen` is notified under every `net:` section and a TCP `listen` with no `net.listen` is
  the supervisor's to refuse. Autobind reached no `BIND_TCP` check, so R6's sentence on `listen()` held for no such run.
- 2026-10-25, R5 (ADR 0064): the harness hook's grant is an exec rule the runtime adds to the table, granted as any exec
  rule; it is never made for a binary or loader under a write, ask or `deny_read` entry.
- 2026-10-25, E9 and E10 (ADR 0067 D3): the builder leaves out
  exactly the name compile recorded for an absent row (`AbsentRow.At`), which the tier models refuse a read beneath, and
  fails `Prepare` when that name's directory changed since compile; a row that is a symlink leading nowhere is recorded
  by where the link leads. Before, the builder walked up to whatever existed, the ledger recorded the refused reads
  allow, and a token written through a dangling link was read. E10 states what the record says for a file created at
  an enumerated level.
- 2026-10-25, R3 and E9 (ADR 0067 D3): the built-in rows absent at
  compile, `RuleTable.AbsentDenyRead`, are deny targets too, so the directory each would appear in is enumerated and
  a token file created there during the run (a login in another terminal) is refused. Before, such a file was read,
  unless it lay directly in a home directory another row (`~/.ssh`) had made R3 enumerate.
- 2026-10-25, R16 and R17 (ADR 0077): `reason.reads: on` notifies every read open at tier landlock
  where nothing else does, so a `deny_read` hit is a refused line under every record mode; every such line at tier
  landlock carries `mechanism: landlock`. The default is off, measured (`test/bench/read-notify`).
- 2026-10-24, R6 and R21 (ADR 0070): a contract with no `net:` section and no `host_sockets: true` is
  in the unix-only state (`unixRestricted`): no net right is handled, but `RESOLVE_UNIX` is, at ABI ≥ 9, granted under
  every write entry and on the runtime's unix: grants, and R11c's `bind(2)` notification is installed. Only
  `host_sockets: true` handles no unix right now (`TestNoNetSectionHandlesNoUnixRight`,
  `TestUnixOnlyStateHandlesResolveUnix`).
- 2026-10-20, R11d for an observe run: an observe
  run's gap line for a copy a non-dumpable process could not have read is written once per process, naming no binary,
  where every such process of the run shared one (supervisor R31).
- 2026-10-20, R11d for an observe run: it says how an
  observe run records the operations its arms notify. Its supervisor wrote a `refused` line for a cork and for a copy
  whose descriptor it could not read, which it had continued, and the ledger posted it to `last-refusal.json`; each is
  now a `gap what=record` line (supervisor R30).
- 2026-10-20, R11d for an observe run: the observe filter installs the
  pending-frame arms where the contract decides datagrams (`BuildFilter`'s `frames`, `observe.FilterFunc`), so an
  observe run records every operation the enforcing run refuses `datagram-corked`; it installed none, while its
  supervisor applied the decisions, so the record missed the unaddressed `MSG_MORE` send, the cork, `sendfile` and
  `splice` (`TestObserveFilterCarriesThePendingFrameArms`, `TestPrepareAsksForThePendingFrameArms`; end to end
  `TestIntegrationObserveRecordsPendingFrames`). Rejected: amending R11d to say observe records only notified sends,
  which would leave learn mode and `drift` a record that under-reports what the contract refuses.
- 2026-10-20, R11d's cost: it now says that a copy whose output descriptor
  the supervisor cannot read is refused, so at tier 1 a non-dumpable process's every `sendfile` and `splice` fails in
  a run that decides datagrams, a file copy included, recorded `refused` with rule `fd-unreadable`. It said only that a
  file copy is notified.
- 2026-10-20, R11 and R11d (new, ADR 0008's design note): in a run that
  decides datagrams the filter notifies a `sendto` with no address carrying `MSG_MORE`, `setsockopt(UDP_CORK)` at
  `SOL_UDP` or `SOL_UDPLITE`, and every `sendfile` and `splice`, which the supervisor refuses `datagram-corked` on a
  socket that can hold a UDP frame. Before, a frame those left pending carried a later relayed or approved datagram to
  its own destination under a line naming another.
- 2026-10-27, R4 (ADR 0043 D6): a target the plan leaves out is not held for the run; its name, which
  the containment plan reads, comes from a descriptor opened and closed at once. Held, each one cost a descriptor of the
  launcher's budget (E11) that nothing used, and a project of 4,500 `.env` files beneath a write entry, whose plane
  rows compaction holds, was refused at Prepare at every tier.
- 2026-10-16, R11 (ADR 0041 Step 2): the write-gate filter has golden dumps on both architectures
  (`TestWriteGateFilterGolden`), and `TestWriteGateNotifiesChmod` holds the arm end to end; a 10k-file `tar xpf` with
  10,101 mode changes costs about 51 µs per change under a write gate (gate.md R4).
- 2026-10-05, R11: a test build's `TEGO_TEST_FILTER_OMIT` leaves named syscalls out of the
  notify arm and the root-tier arm, so the governed-run cells of the plane's `bpf` and `key_permission` hooks reach
  them; in a product build the seam is a function that omits nothing.
- 2026-10-05, R21, R22 and §10's integration list: `TestIntegrationUnixConnect` and `TestIntegrationUDPPorts` run the
  ruleset `Prepare` built in a helper that installs no seccomp filter, so a refusal is the kernel's Landlock alone. At ABI ≥ 9 an
  undeclared pathname socket's connect is `EACCES` (the declared socket and one under a write entry connect), and at ABI ≥ 10 a
  send or connect to an undeclared UDP port and a bind to a fixed one are `EACCES`, delivering nothing, while an ephemeral
  bind and the declared port go through; below those ABIs the same calls succeed, which is the supervisor's to decide. The kernel
  matrix's `fedora-7.2` row (ABI 10) is the one place the first half runs, and a guest told its row (`TEGO_VM_ROW`) fails there
  if the kernel reports less. First runs, 2026-10-05: both pass on Fedora's 7.2.9 (ABI 10), with the kernel refusing as above, and
  their below-ABI halves pass on 6.17 (ABI 7).
- 2026-10-05, R11b (new; ADR 0041 D6): under a net gate the filter refuses `setsockopt`
  of `IP_OPTIONS`, `IPV6_RTHDR`, `IPV6_2292RTHDR` and `IPV6_2292PKTOPTIONS`; a sibling could add a source route
  between the supervisor's options read and its relayed connect.
- 2026-10-05, R4, R6, R10, R11, R22, E30, I8: the spec follows the code `net.listen` and strict client assurance brought: `BIND_TCP`/`BIND_UDP` on declared listener ports,
  `bind`/`listen` notified under `net.listen`, the `ClientDeny` and `IP_BIND_ADDRESS_NO_PORT` arms; R4 names
  `pkg/policy/fsplan` and the held-name refusal; I8's test is sys's.
- 2026-10-17, R10 (ADR 0041 Stage B review): under held completion the Landlock syscalls are
  answered `ENOSYS`, so no process of the run makes a domain of its own that the open deputy does not share.
- 2026-10-16, R11 (ADR 0041 Step 2): an `fs.write` gate also notifies the xattr and
  `chown` families at every record level; neither was notified under any option, so `setfacl` changed a mode outside
  the worktree that the gate refused to `chmod`, with no score and no line.
- 2026-10-05, R11: an `fs.write` gate notifies the chmod family under `summary`/`off`
  too; it was notified under `record: full` only, so the gate refused a chmod there and never saw one otherwise.
- 2026-10-16, R5 (agent-contract.md R8a): a loader that is or leads through a `/proc` path is `ErrLoaderRefused`.
- 2026-09-30, R5 (E29): an `fs.write`/`fs.ask` entry of `/` contains the loader too; it passed before.
- 2026-09-30, R3 (E33): a level that cannot be listed (`EACCES`) has an empty snapshot and grants no sibling.
- 2026-09-30, R22: `BIND_UDP`, handled at ABI ≥ 10, is granted on the ephemeral port (0) only; a fixed UDP port
  stays refused.
- 2026-09-30, R11a: at tiers 2 and 3 a run the plane decides with step C gets no refusing arm (enforce-plane R27).
- 2026-09-29, R2: the ABI-3 row refuses an `O_TRUNC` open of access mode 3 too, not only `O_RDONLY`.
- 2026-09-29, R10 (TIER3-PLAN T13): the `io_uring_*` arms leave the filter of a contract declaring `io_uring: true`
  where a decision plane mode decides the run (ADR 0018 (5)).
- 2026-09-29, R11a: tier 2's capability line clears `exec.deny` by the inherited tier-1 row (`exec.anonymous`).
- 2026-09-29, R18: the rule names the child stage's `sys.RestrictSelf`; the unused `RestrictSelf` is deleted.
- 2026-09-29, R7: the process-scope arm notifies `prlimit64`, `setpriority`, the `sched_set*` calls and
  `ioprio_set` on another process at every ABI.
- 2026-09-22, R6: with no `net:`, `RESOLVE_UNIX` is unhandled at ABI ≥ 9 too.
- 2026-09-28, R4, R5, R6 (ADR 0028 S1): the plan's containment, nesting and ancestor questions and the exec and
  net verdicts compile --test reports are the decision core's (`internal/policy/decide`).
- 2026-09-22, R10: `open_by_handle_at` joins the `ENOSYS` set.
- 2026-09-23, R6: the `models[]` guard under `capture: forwarder` is the supervisor's
  alone.
- 2026-09-23, R16 memfd arms: the sealing arm refuses `MFD_HUGETLB`; the refusing arm is installed below 6.3.
- 2026-09-23, R18, R19, R20: `LOG_*` flags never retried away; `net.unix_abstract_scope` row at ABI ≥ 6; R20
  cited for `landlock_add_rule` only.
- 2026-09-24, R5: a hard link of a granted binary is refused by supervisor R16b.
- 2026-09-24, R7: below ABI 6 the filter notifies the signal and
  owner-setting calls and answers `pidfd_send_signal` `ENOSYS`.
- 2026-09-24, R10: `clone3` joins the `ENOSYS` set (`CLONE_INTO_CGROUP` escape).
- 2026-09-24, R11: System V IPC notified unconditionally.
- 2026-09-29, R11 (ADR 0017 conformance): `truncate(2)` notified from ABI 3, the chmod family under `record: full`.
- 2026-09-29, R11: `mknod`/`mknodat` notified unconditionally.
- 2026-09-29, R5: the `#!` line is split as `binfmt_script` splits it (CRLF, whole argument).
- 2026-09-29, R11: the rule lists the namespace arm (E24) and the tier-2/3 root-tier `EPERM` arm (ADR 0033).

## 6. Edge cases

E1. Landlock disabled at boot (`landlock=0`): `ErrLandlockUnsupported`; `Select` excludes this backend first.
E2. Kernel < 5.13: same handling as E1 (`ENOSYS`).
E3. ABI 1 (unsupported floor, ARCHITECTURE §14): `doctor` should never offer tier 1 here; if reached, `REFER`
drops silently (R2), making cross-directory link/rename over-restrictive, never under.
E4. ABI 2 with `net.allow` non-empty (AL2023 default): no `netRule` is possible below ABI 4 — an *allowed*
host is still refused by Landlock; `Capabilities()` reports `net: none` for ABI < 4 (R19), not
"port allow-listed."
E5. `deny_read: ["/"]`: no parent to walk — `compile` rejects it (`schema`) before `Prepare` ever sees it, judged on the resolved path so a symlink to `/` is rejected too; `Prepare` fails closed on the same resolved path as a backstop (`ErrRulesetBuild`).
E6. Enumeration crosses a directory with tens of thousands of entries (e.g. `/nix/store`): one fd per sibling,
uncapped — real cost, no normative threshold set (§11).
E7. Two `deny_read` entries share an ancestor: dedupe by `(st_dev, st_ino)` read once per fd, not by path
string (transient use only — never persisted as identity, per ADR 0010's ban on `(device, inode)` identity).
E8. A sibling is itself another `write`/`ask` entry: grants union harmlessly; R4 only triggers if the
*shared parent*, not the sibling, is itself a write dir.
E9. `deny_read` target deleted since `compile`: target's own fd (`Access:0`) gets `ENOENT`; harmless no-op —
enumeration is path-string-driven, not existence-driven. *Amended 2026-10-25 ([ADR 0067](../adr/0067-agent-token-stores-and-credential-rows.md) D3):*
a built-in row absent at compile (`RuleTable.AbsentDenyRead`) is a target the same way, by the name compile recorded
for it (`AbsentRow.At`: the first name on the row's path missing at compile, directly beneath the nearest directory
that existed; for a row that was a symlink leading nowhere, on the path the link leads to). That directory is held and
enumerated with `At` left out, so a file created at the row during the run gets no rule (E10) and its read is refused;
an `At` present by `Prepare` is held and denied as the node it is. Any other state, `At`'s directory gone or no longer
a directory, or either reached through a symlink compile did not see, fails `Prepare` with `ErrRulesetBuild`
("recompile the contract"), since the ruleset would leave out another name than the one the tier models refuse
(*amended 2026-10-25*). Compile records no row beneath a regular file, nor one a
write or exec.allow directory entry covers (`snapshotAbsent`; `TestAbsentRowLeavesOutTheNameCompilePredicted`,
`TestAbsentRowDriftIsRefused`, `TestTokenStoreCreatedDuringRunIsRefused`, `TestTokenStoreMadeBeforeTheRunIsRefused`).
E10. File created at an enumerated level after `landlock_restrict_self`: no rule exists for it (domains are
immutable post-restrict) — unreadable, more restrictive than intended, documented limitation (SEMANTICS §2).
*Amended 2026-10-26 (ADR 0069's note of that date):* the same holds for everything beneath a directory made
there, and for a listed name replaced by a new inode (an editor's save by rename). The handle keeps the enumeration
(`Snapshot`: each ancestor's listing, the inodes granted `READ_FILE`), and the supervisor refuses such a read or exec
itself, `EACCES`, recorded `refused`, `read-denied`, rule `deny-read-snapshot`, where the line said `allow`.
*Amended 2026-10-26 (ADR 0067 D3):* a read at or beneath an absent built-in row's `At` is
answered refused, `read-denied`, by the row itself in the decision core (E9; `decide.AbsentRead`), so the line names
the token store rather than `deny-read-snapshot`; the snapshot refusal covers the other names made mid-run.
E11. Fd exhaustion (large `deny_read` enumeration or many `exec.allow` directory entries): the plan is held to the
launcher's descriptor budget (`FDBudget`: the soft `RLIMIT_NOFILE`, raised to the hard limit where lower, less the
descriptors held when Prepare starts and a reserve of a sixteenth of the limit, 64 to 256), read before the first open;
the open past it is not made (`FDCapError`, errors.Is `ErrFDExhausted`), so a large table meets the named cap, never
`EMFILE`. An `EMFILE`/`ENFILE` another holder causes is still `ErrFDExhausted`. Either way `Prepare` closes everything
opened so far, returns error; exit 125 naming the count and, for the budget, the cap (enforce-plane §2.4 condition 7).
E12. Symlink in a declared path: identity is fixed at `O_PATH` open time, not at `compile` time (ADR 0010) —
a target that moved between `compile` and `run` is whatever the fd resolves to now, not re-validated here.
E13. Non-UTF8 path bytes from directory listing: `os.DirEntry.Name()` preserves them as-is; grants compute
correctly; diagnostics must use `%q`, never raw `%s`, for any listing-derived path.
E14. Contract drifted between `compile` and `run` (a script's `#!` now names an ungranted interpreter):
`Prepare` re-resolves live and fails closed (R5), never silently narrows the grant.
E15. Two concurrent runs with overlapping `deny_read` under the same `$HOME`: fully independent fd sets and
rulesets — Landlock domains are per-task-credential, no shared state (ARCHITECTURE §3).
E16. `exec.allow` names a basename shadowed by a `uv`/`pyenv` shim at a different inode: two distinct grants,
never conflated (SEMANTICS §4); an unlisted one is refused like any other.
E17. A venv's `python` symlink to the system interpreter: same inode, grant transfers for free.
E18. Loader resolution is per-binary only for individually-named `exec.allow` entries, never pre-scanned for
binaries reachable only through a directory grant — a binary needing an unusual loader inside a granted
directory is refused at the loader-open step even though the binary itself was grantable (§11).
E19. Clock changes mid-run: irrelevant — nothing here reads wall-clock time; the ruleset/filter are static.
E20. `ctx` cancelled during `Prepare` (fast stop before the child forks): early return, fds closed, no
`run_start` was ever written, so nothing to sweep.
E21. `exec.allow` target is a FIFO or device node: `landlock_add_rule` with `EXECUTE` fails
(`EINVAL`/`ENOTDIR`-class); propagated as `ErrRulesetBuild` — defense in depth, `compile` should reject first.
E22. Very large `RuleTable` (thousands of individually-listed `exec.allow` binaries): `Prepare` scales
linearly, no hard cap; `ctx` check keeps it cancellable; no performance budget row exists yet (§11). That
includes thousands of `deny_read` targets, which the built-in `.env` scan hands over one per `.env` file where
the agent writes (up to 50,000): E29 (a)'s nesting filter looks each target's ancestors up in a set, linear in
the targets (15,000 planted `.env.<n>` files start a run in 0.72 s, 5,000 in 0.36 s;
`TestOutermostScalesLinearly`).
E23. PID reuse: irrelevant here — this package holds no PID-keyed state; belongs to the supervisor's
`ID_VALID` handling.
E24. Binary upgrade mid-run (VERSIONING.md rename-install): the live launcher's in-memory `handle` is
unaffected; a new run after the upgrade builds independently against the new binary.
E25. Machine ABI beyond the highest known profile (>11, or a kernel newer than the highest tested row): clamp
to the ABI-11 request rather than error or guess an encoding (R2) — forward-compatible, never crashes.
E26. `write` dir and `deny_read` target are the same path (a `compile` bug reaching `Prepare`): R4's
writable-parent check catches the degenerate case (target is trivially "at or below" itself) and silently
skips the deny rather than building a contradictory ruleset — should still be a `compile`-time hard error.
E27 (new). `RLIMIT_NOFILE` is a whole-process budget: the ledger writer's file, the cgroup directory fd
(`internal/runtime/cgroup`), and the run-dir `flock` open in the same launcher process *before* `Prepare`
(ARCHITECTURE §5); a large `deny_read`/`exec.allow` enumeration can starve fds those components need
*afterward* (e.g. a ledger blob rotation). E11's handling is local-only; no cross-component reservation exists
yet (§11).
E28 (new). TOCTOU within the sibling-enumeration walk (distinct from E12's single-target case): R3's `readdir`
at level `L` is one snapshot; a concurrent rename between the snapshot and the matching `landlock_add_rule`
calls can add a rule for a vanished sibling (harmless, mirrors E9) or leave a since-appeared sibling unruled —
**more** restrictive than intended, not less, consistent with E10's "gaps lean restrictive" posture, so no
special handling beyond documenting it. The vanished sibling has two windows. Gone before its own
`O_PATH` open, it is skipped (`ENOENT`, as E9). Gone after it, the held fd keeps the unlinked inode, and
`landlock_add_rule` takes the rule on it (checked on ABI 7), where no path reaches it any more. Neither
window can make the build fail. An `EBADF` from `landlock_add_rule` means something other than the builder
closed one of its numbers: a held number, or the ruleset's, for which the kernel answers `EBADF` also once an
`O_PATH` open has taken it (I12). That is the §7 "held descriptor lost" row, not this case.
E29 (new). A *second, more specific* input widening what a first input denies — two shapes, one rule. (a) A
`deny_read` target nested inside another (`deny_read: ["~/secrets", "~/secrets/prod/app.key"]`, or the same
pair arriving through `extends`, which concatenates the parent's list with the child's): the inner target is
dropped before enumeration (R3), because walking it would grant the read set to the outer target's other
children. (b) A `PT_INTERP` string naming contract-governed ground (`~/.ssh`, a directory, a file the agent
wrote under its own `fs.write` entry): the loader grant is confined to a regular file outside every
`write`/`ask`/`deny_read` entry (R5). Both lean fail-closed — a dropped target is still denied by the outer
entry, and a refused loader stops the run with a named cause instead of an unexplained `EACCES` at `execve`.
E30 (new). Landlock's network hooks check `LANDLOCK_ACCESS_NET_*` only for `sk_is_tcp()`/`sk_is_udp()` sockets
and `else return 0` for everything else (`security/landlock/net.c`), so an `IPPROTO_MPTCP` socket sits outside
the domain's net rules entirely — the shape go-landlock hit (issue #50) when Go 1.24 made MPTCP the default
for `net.Listen`. `connect(2)` keeps its primary path and loses only R6's in-kernel backstop (it is notified at
every ABI and the supervisor is authoritative, R11); `bind(2)` is notified only under a `net.listen` list (R11)
and otherwise has no path at all, so the filter refuses `socket(_, _, IPPROTO_MPTCP)` with `EPROTONOSUPPORT` — what a kernel without
`CONFIG_MPTCP` returns, so a runtime that probes for MPTCP falls back to a classic socket the rules do govern
(Go falls back on any error from the attempt, `net/mptcpsock_linux.go`). Residue, recorded rather than fixed:
other protocols the hooks also skip (SCTP, DCCP) keep their outbound direction covered by the `connect`/
`sendto`/`sendmsg` notifications, but their `bind()` is as unseen as MPTCP's was where the contract has no
`net.listen` (with one, R11 notifies `bind`; amended 2026-10-05), and no port right grants them either: Landlock's
port rights are TCP's and UDP's. Their outbound direction is not covered by those notifications
either: SCTP associates through `setsockopt(SOL_SCTP, SCTP_SOCKOPT_CONNECTX)` and sends with a peerless `send()`,
which neither the `connect` notification nor the addressed-`sendto` arm sees (reproduced
on 6.17). So under a `net:` section the filter decides `socket(2)` and `socketpair(2)` on their scalar arguments by
an allowlist of what the network rules govern: `socket` admits `AF_UNIX` (any type), `AF_NETLINK` as `NETLINK_ROUTE`
alone (*amended 2026-11-01*, ADR 0128: an unaddressed `send(2)` is not notified, so another protocol refused only at
its addressed sends still reached the kernel) and, on `AF_INET`/`AF_INET6`, a `SOCK_STREAM` with protocol 0 or `IPPROTO_TCP`, a `SOCK_DGRAM` with 0 or
`IPPROTO_UDP`, and, when the contract has a port-0 (ICMP) entry, a `SOCK_DGRAM` with
`IPPROTO_ICMP`/`IPPROTO_ICMPV6`; `socketpair` admits `AF_UNIX` only. Every other triple is notified to the
supervisor, whose handler refuses it (`EPROTONOSUPPORT` for an inet type or protocol and for a netlink protocol,
`EAFNOSUPPORT` for a family, what a kernel without them answers, so runtimes fall back) and records a `refused` line, reason `net-not-allowed`,
rule `unmatched`, naming the triple; it has no `CONTINUE` path. The MPTCP arm above stays first and silent:
runtimes probe MPTCP and fall back, which is no policy event. SCTP, UDP-Lite, DCCP and every family outside the net
rules (`AF_VSOCK`, `AF_TIPC`, `AF_RDS`, `AF_SMC`, `AF_PACKET`) are refused at creation; with no `net:` section
nothing changes (SEMANTICS §1). A notification the supervisor has no entry for is answered `ENOSYS`, not
`CONTINUE`, and a test walks every filter variant on both arches and fails when a notified syscall has no handler.
`io_uring`'s socket op stays unreachable (R10's `ENOSYS`). The handle reports this as
`NetworkGuarantees.SocketFamilies` (the arm installed under a `net:` section with io_uring refused; amended
2026-10-16, ADR 0018 PR 2), which a root tier extends: `cgroup/sock_create` refuses an inet socket outside the
allowlist on any path the filter misses, and a plane mode's `socket_create` any family, io_uring's op included.
*Amended 2026-10-17 (ADR 0018 (7)):* the arm also notifies `setsockopt(SOL_TCP, TCP_ULP)`
(`tcpULPTest`, both arches, on the level's and option's low 32 bits), and the supervisor refuses it, whatever the name,
with `ENOENT` and a `refused` line (op `setsockopt`, target `TCP_ULP "<name>"`): the smc module's `smc` ULP turned an
unconnected TCP socket the allowlist admitted into `AF_SMC` in place, a socket none of the creation arms or hooks see.
The decision is on scalars; the name is read only for the line. `SocketFamilies` is reported only with this arm in
place (it is part of the socket arm), and at a root tier `cgroup/setsockopt` refuses the same option on the paths the
filter does not see, io_uring's `SOCKET_URING_OP_SETSOCKOPT` among them.

E31. Truncation below ABI 3 (R2's ABI-3 row). The
kernel has no truncation hook before ABI 3 at all: "File truncation could not be denied before the third Landlock
ABI, so it is always allowed when using a kernel that only supports the first or second ABI"
(`Documentation/userspace-api/landlock.rst`), and 6.1/ABI 2 is ARCHITECTURE §14's tested floor. Two shapes reach
it: `truncate(2)`, which takes a path, needs no fd and is in no notify table; and `open(path, O_RDONLY|O_TRUNC)`,
whose Landlock access is `READ_FILE` only (with its access-mode-3 twin `open(path, O_ACCMODE|O_TRUNC)`, whose fd
has neither `FMODE_READ` nor `FMODE_WRITE` so Landlock checks nothing while the VFS still truncates) — it is notified under R12's flag mask, but the supervisor's open handler
is record-only and answers `CONTINUE`, so the notification would record the truncation rather than prevent it.
Below ABI 3 the filter refuses them all with `EPERM`: an `O_TRUNC` open passes only with access mode exactly
`O_WRONLY` or `O_RDWR`. Deliberately coarser than the contract: a `truncate(2)` inside a
declared `write` dir is refused too, because the filter cannot safely resolve a path argument (R11) and
over-restriction is the fail-closed direction; `O_RDONLY|O_TRUNC` is unspecified behaviour in POSIX and mode 3 is not a POSIX
mode at all, so refusing them costs nothing legitimate. The conformance suite holds this: on a kernel below ABI 3
its kernel runner wants every truncate cell refused with `EPERM` and no ledger line, in every tier and plane mode
(each keeps this filter), whatever the contract grants (`test/conformance` `Cell.WantOn`); `compile --test` has no
truncate action, so its rows for those cells are `fs.write`, the answer every tier gives from ABI 3.

E32. A deny node shares its inode with another entry reached by another name — a
hardlink of a file target, a bind mount of a target or ancestor directory. Landlock keys rules by inode, so the
inode decides, and `Prepare` compares `(st_dev, st_ino)` of the held fds (E7) rather than strings. (a) An *earlier*
stage already holds it (`fs.write`/`fs.ask`/`fs.watch`/implicit entries are held before `deny_read` is enumerated).
An identity-only entry (`fs.watch`, `fs.ask`, implicit) is re-marked as the deny node, so the seal (R3) applies to
it; left under its own kind, a hardlink sibling or a `PT_INTERP` would union `READ_FILE` onto a watched credential
file and read it by both names. An `fs.write` entry already carries rights that cover exactly what the node denies:
that is R4 decided by identity, and `compile`, which compares paths, cannot have marked the `deny_read` entry
unenforced, so reporting it unenforced here would break I5 — `Prepare` fails closed (`ErrRulesetBuild`, both paths
named). (b) A *later* enumerated sibling that is a node's inode keeps the node's rights: it is the same content,
and leaving it with the node's rights is the deny itself. (c) A *later* declared grant — any exec grant (an
`exec.allow`, command, `mcp` or interpreter binary, an `exec.allow` directory, R5) or, at ABI ≥ 9 only, a pathname
`unix:` socket (R21) — whose inode is a deny node fails closed (`ErrRulesetBuild`, both paths named and the reason
given), because a grant dropped quietly would surface only as `EACCES` at `execve`/`connect` behind a `compile
--test` row that says allow. The two arms fail for different reasons. An exec grant needs `READ_FILE`, so granting
it would read what `deny_read` denies. `RESOLVE_UNIX` carries no read right, but the seal is kept by kind, not by
right, so the ABI ≥ 9 backstop would be dropped and Landlock would refuse the `connect` that `net.allow` declares.
Below ABI 9 a pathname `unix:` entry holds no fd (R21), so the same contract prepares and the supervisor alone
decides. A declared grant *beneath* a target is a different inode and keeps its rights (I11). (d) A level that is a
target's own inode is a bind mount of the whole target on the path to another target. That level is neither held
nor listed, and neither is any level beneath it by name. Each of those lies inside the target however many
directories down, though only the first is the target's inode, and listing any of them would grant the target's
contents as siblings, on their own inodes, so under every name. This is not E29 (a): `decide.Outermost` compares strings
and cannot see that the second target is inside the first, so the second target is not dropped. It keeps its own
`Access: 0` entry, which adds no rule. What (d) skips are the levels inside the target, which E29 (a) would never
have walked either. The levels above the alias are still walked as the second target's ancestors, which is the same
walk any target outside the first would get. **Limitation, recorded rather than fixed:** the enumeration sees only
the names it walks, and tier 1 has no deny rule to put on an inode, only grants to withhold. (i) Content inside a
*directory* target that has a name at an enumerated level is that level's sibling. Examples are a hardlink of a
file in the target and a bind mount of a directory in it: `~/keycopy` hardlinked to `~/.ssh/id_rsa`, with `~` a
level. `sibling` grants it on the content's own inode, and Landlock keys the grant by inode, so the content is
readable through every name, the target's own path included. The same holds for a bind mount of *part* of a target
on the path to another target: it and every level beneath it are listed as ordinary levels, and their siblings are
granted on inodes inside the target. Only a scan of the target's whole subtree could tell such a name apart, which
R3 does not do. A *file* target's own hardlink is the target's inode and stays sealed, (b). (ii) The target's
content reached through a name *beneath* a granted sibling is readable through that name alone: a hardlink one
directory down, a bind mount of the target or of part of it under a sibling directory. The target's own path still
denies it — except where a grant is keyed on that content's own inode, I11 (3): then every name reads it, the
target's own path included. `compile` prints each entry's mount and warns on mount points (ARCHITECTURE §10).
E33 (new). A `deny_read` target under an ancestor the launcher may search but not list: mode `--x` to it, such as
another user's `0711` home or a directory made `0111`. Holding it `O_PATH` needs only search, but R3's listing
reopens it for reading, which DAC refuses with `EACCES`. That level then lists as empty: it is still held and sealed
with `READ_DIR` (plus `EXECUTE` as R3 (3) says), the target is still sealed, and no sibling at that level is granted.
The run prepares, and `deny_read` is enforced. The gap leans restrictive, as E10 and E28 do: a name at that level
the agent could have opened by name, having search on the directory, is refused by Landlock. Any other failure of
the listing still fails the build (`ErrRulesetBuild`, or E11's exhaustion).

**Changes.**
- 2026-10-27, E11 (ADR 0043 D6): a `deny_read` target R4 leaves out holds no descriptor for the run,
  so thousands of `.env` files beneath a write entry no longer pass the cap at every tier
  (`TestLeftOutDenyReadTargetsHoldNoDescriptor`).
- 2026-09-30, E11 (enforce-plane §2.4 condition 7): the plan is held to the launcher's descriptor budget and refused
  naming the cap before any open meets `EMFILE`.
- 2026-09-30, E33, R3: an ancestor that cannot be listed (`EACCES`) grants no siblings instead of failing `Prepare`.
- 2026-09-30, E31: the conformance kernel runner wants the filter's `EPERM` for a truncate cell below ABI 3 (it
  wanted the contract's allow, and failed on AL2023's 6.1).
- 2026-09-29, E31: an `O_TRUNC` open with access mode 3 (`O_ACCMODE`) is refused below ABI 3 like `O_RDONLY`.
- 2026-09-24, E22: the `deny_read` nesting filter is linear.
- 2026-09-28, E29, E32 (ADR 0028 S1): the nesting filter is `decide.Outermost`.
- 2026-09-24, E30 (ADR 0018 PR 1): `socket`/`socketpair` decided by an allowlist under a `net:` section;
  unhandled notifications answered `ENOSYS`.
- 2026-09-24, E5: `compile` rejects a `deny_read` resolving to `/`; the backstop reads the
  resolved path.
- 2026-09-29, R5 / I11 (1): an exec grant inside a `deny_read` stays readable at tier 1, now a stated exception in
  SEMANTICS §2 (conformance cell `exec/read-file-inside-exec-entry-directory-inside-deny-read`).
- 2026-10-16, E30 (ADR 0018 PR 2): the socket arm is reported as `NetworkGuarantees.SocketFamilies`; a root tier adds `cgroup/sock_create` and the plane's `socket_create` for the paths the filter misses.
- 2026-10-17, E30 (ADR 0018 (7)): the socket arm notifies `setsockopt(SOL_TCP, TCP_ULP)`, which the
  supervisor refuses with `ENOENT` and a line; a ULP had turned an admitted TCP socket into `AF_SMC`.

## 7. Failure modes and handling

| Failure | Detection | Response | Ledger | Exit / user-visible |
|---|---|---|---|---|
| Landlock unsupported (E1/E2) | probe errno | `Select` excludes tier 1 pre-`Prepare` | none | `doctor` names next tier + fix |
| Fd exhaustion (E11/E27) | the budget reached (`FDCapError`), or `EMFILE`/`ENFILE` | close all opened, return err | none (pre-`run_start`) | exit 125, count (and cap) named |
| Path vanished (E9/write analog) | `ENOENT` on `O_PATH` | `write`: created by `run` (0755; at a root launch as the uid and gid the child drops to, `Run.Drop`, so the agent owns it and the mkdir is judged as that user's); else fail closed | none | exit 125, path named |
| Missing interpreter grant (R5) | `#!` target not in exec set | fail closed | none | exit 125, script + interpreter named |
| Loader refused (R5/E29) | `PT_INTERP` resolves onto a `write`/`ask`/`deny_read` path, or is not a regular file | fail closed | none | exit 125, binary + loader named |
| Deny node aliased (E32) | a `deny_read` target or ancestor is the inode of an `fs.write` entry held first, or of a later exec grant or (ABI ≥ 9 only, R21) `unix:` grant | fail closed | none | exit 125, both paths named with the reason: an exec grant would read the node, a `unix:` backstop would be dropped |
| `landlock_add_rule` rejects mask/fd (E21) | non-Landlock errno | wrap, fail | none | exit 125, generic |
| Held descriptor lost | after the last `landlock_add_rule`, or when any `landlock_add_rule` fails: a held number no longer names the (dev, ino) it was opened on, or `statx` (`AT_STATX_DONT_SYNC`) fails other than `EBADF`, so what it names is unknown; or the ruleset number does not answer an empty `landlock_add_rule` with `ENOMSG`, as only a Landlock ruleset does (`EBADFD`: another file; `EBADF`: closed, or an `O_PATH` file, which the kernel's `fdget` lookup does not see) | fail closed: the ruleset is never returned, and a number not shown to be the builder's own is left open, since it may be another owner's by then; a held number of unknown identity is asked again at cleanup and closed only if it then names its own file | none | exit 125, the entry or the ruleset, the number, and what it names now or the errno |
| `ctx` cancelled (E20) | `ctx.Err()` between entries | close fds, return | none | stop semantics, no `run_start` |
| Child's `landlock_restrict_self`/`seccomp` install fails | out of scope (`launch`) | n/a here — child aborts before step 8's `execve` | none | **exit 125** (corrected, was 126 — Corrections C3), one-sentence stderr naming the failing syscall |

This package never writes the ledger itself; every row's ledger effect is the caller's action once `Prepare`
reports success or failure. Contract: build correct kernel objects or fail loudly before any process forks.
The last row is deliberately distinct from RUN-IDENTITY.md's exit 126 (`run_end reason=exec-failed`), which is
reserved for a failure to exec the **target command** itself (`EACCES`/`ENOEXEC`, or the tier refusing exec on
it) — installation of the child's own kernel enforcement objects never reaches that point; it is "Tego failed
before exec" (RUN-IDENTITY.md's own wording for 125), and correctly writes no ledger row.

**Changes.**
- 2026-09-29, path vanished row: at a root launch a missing `write` directory is created as the dropped user, not
  root (`TestMissingWriteDirIsCreatedAsTheDroppedUser`, `TestRootMissingWriteDirIsTheDroppedUsers`).

## 8. Invariants

I1. No `Handle` is ever returned with a partially-built fd set (all-or-nothing `Prepare`, E11/E20).
I2. `rulesetFD` is never used for a second `landlock_add_rule` after the child's `landlock_restrict_self` —
enforced structurally (no `AddRule` on `Handle` post-`Prepare`), not by a runtime check.
I3. Every `openPath` with `Access != 0` maps to exactly one `landlock_add_rule` call, every `Access == 0` to
zero; every `netRule`/`unixRule` maps to exactly one call — tested against a fake `landlock_add_rule` call log
(the `Options.syscalls` seam, §2/§4).
I4. The write-side mask is always handled, even for an empty `rt.FS` and for a contract with no `fs:` section,
so "all writes refused" is true by omission (SEMANTICS §1, whose no-`fs:` row now says so) and the implicit
entries stay unwritable — tested directly on an empty-`FS` fixture and on a no-`fs:` contract.
I5. R4's unenforced decision never disagrees with `compile`'s diagnostic for the same contract — cross-check
integration test running `agent.Compile` and `Prepare` against the same fixtures. The assertion stays although
both sides ask one question (`fsplan`'s `FirstCover`, the containment ADR 0028's core plans with): compile asks it of the paths it
resolved, `Prepare` of what they resolve to at the run, and a containment that changed between the two (a
symlinked write entry that now encloses a `deny_read` target) is reported, not trusted.
I6. The filter never notifies a syscall its own arch/x32 guard would already `ENOSYS` — guard is always the
first instructions in the assembled program, tested by inspecting instruction order.
I7. `Close` is idempotent and never panics on a zero-value or double-closed `handle`.
I8. The ruleset is never applied with `no_new_privs` resting on the ABI-11 flag alone: the unprivileged child
stage sets it by `prctl` (step 4) before `sys.RestrictSelf`, and the privileged order applies the ruleset with
`CAP_SYS_ADMIN` and sets it after the credential drop unless the contract says `setuid: true` (ADR 0033), so a
flag the kernel refuses and the retry drops leaves the bit as it was. A call the kernel accepts with the flag is
cross-checked with `PR_GET_NO_NEW_PRIVS`, and a bit left unset or unreadable fails the stage (sys's
`TestRestrictSelfFallbackAndNoNewPrivs`, the check ported from the deleted `RestrictSelf`).
I9. Declaring `SCOPE_SIGNAL`/`SCOPE_ABSTRACT_UNIX_SOCKET` never blocks the supervisor's control of the agent —
covered by the integration suite (§10), not unit-testable in this package alone.
I10 (new). `Capabilities()`'s net/unix/udp dimensions (R19) never claim a right this package did not actually
build a rule for at the stored ABI — tested against the same fake call log as I3, one case per ABI band
(< 4, 4–8, 9, ≥ 10).
I11 (new). A `deny_read` target's entry carries `Access: 0`, and every enumerated ancestor's only R3 (3)'s
listing rights, for the whole of `Prepare`, whatever name reaches their inodes: rights never union onto a sealed
deny node (R3, E29), and an entry that already carried more fails the build (E32). A level inside a target is
neither held nor listed, save in one shape. A level inside by name goes with its dropped target (E29 (a)), and a
level inside through a bind mount of the whole target is skipped along with every level beneath it (E32 (d)).
The one shape is a bind mount of *part* of a target on the path to another target: it and the levels beneath it
are listed as ordinary levels (E32's limitation (i)). An inode beneath a target holds rights in three cases.
(1) The contract names that entry itself — an `fs.write` entry, an exec grant (R5: exec needs `READ_FILE`), a
`unix:` socket (R21) — by a path inside the target, and those rights reach that entry (and, for a directory, its
subtree). Landlock keys the rule on the inode, so the entry is reachable under every name its inode has, not
under the declared one alone. (2) The inode is E32's limitation (i): content inside a *directory* target that has
a name at an enumerated level (a hardlink of a file in it, a bind mount of a directory in it, a sibling on a level
that partial bind mount makes). It is granted as a sibling on its own inode, so it is readable under every name,
the target's own path included. (3) A grant keyed on an inode that is content inside a directory target, reached
by a name *outside* it: a declared exec or write grant that is a hardlink of a file in the target.
Content-selected `PT_INTERP` grants cannot take this route: R5 rejects multiply linked loaders whenever an
enforced denied directory exists. Explicit grants remain the contract author's choice. So `CapReadDeny` reported as provided (R4) means the subtree really is denied under every name
the enumeration walks, except for the content cases (2) and (3) reach, which is readable under all of them. Names
beneath a granted sibling, which the enumeration does not walk, read the target's content through that name
alone unless (3) applies (E32 limitation (ii)). Tested with a nested target, with a hardlinked target enumerated
as a sibling, with a target an identity-only entry held first (`fs.watch`, implicit; the `fs.watch` shape also on
the real kernel), with a `PT_INTERP` naming one, and with bind-mount aliases of a target (with a second target one, two and three levels beneath the alias,
each with a sibling at its deepest level) and of an ancestor (simulated through `/proc/<pid>/root`, the one
alias an unprivileged test can make).
I12 (new). No `Handle` is returned unless, after the last `landlock_add_rule`, every held number
still names the (dev, ino) it was opened on and the ruleset number still answers as a Landlock ruleset.
Every Landlock ruleset file shares the one anonymous inode, so the ruleset number is asked instead: an
empty `landlock_add_rule` (no access) adds nothing and answers `ENOMSG` for a ruleset, `EBADFD` for any
other file opened without `O_PATH`, and `EBADF` for a closed number or an `O_PATH` file, at every ABI, since
the kernel looks the ruleset number up with `fdget`, which does not see `O_PATH` files. So `EBADF` alone
does not show the ruleset number closed: an `O_PATH` open, the kind the builder makes for every held path,
may hold it by then. The same checks run when a `landlock_add_rule` fails,
and neither `Prepare`'s cleanup nor `Close` closes a number that fails its check. A rule added through a
number that something else in the process closed and the kernel handed to its next open lands on that
file; the check turns that into a failed build, and keeps the cleanup from closing the new owner's
descriptor. Only `EBADF` or another (dev, ino) shows a held number lost. A held number whose `statx` fails
otherwise (`ENOMEM`, a filesystem's `EIO`, a seccomp profile refusing `statx`) fails the check without
being called lost; the cleanup asks again and closes it only if it then names its own file, and otherwise
leaves it open until the launcher exits, with the error saying its identity is unknown. The check cannot
see a held number closed and reopened on the very same inode by the time it looks, nor a ruleset number
closed and reopened on another Landlock ruleset, which answers the probe as the builder's own would: only
`kcmp(2)` against a second reference held for the purpose could tell those apart, and a kernel built
without `CONFIG_KCMP` has no `kcmp`. An overlayfs whose layers sit on different filesystems without `xino`
can renumber a non-directory when it is copied up (ADR 0010). During `Prepare` that reads as a lost number
and fails the build closed. At `Close` it leaves that one fd open until the launcher exits, with the error
saying which. Tested with a fake kernel, whose probe is held to the kernel's answers (a held number
reopened on another file, closed, or of unknown identity; the ruleset's number closed or reopened before a
path rule, reopened before a net rule, after the last rule, and together with a held number; a held or
ruleset number reopened after `Prepare` returned; the ruleset's number reopened on a pipe and on an
`O_PATH` file wherever the two answer differently) and on the real kernel (the probe's answers, for an
`O_PATH` file too; a sibling's number reopened on the `deny_read` target, which Landlock accepts; the
ruleset's number reopened before a sibling's rule on a pipe, which the kernel answers `EBADFD`, and on an
`O_PATH` file, which it answers `EBADF`, and the same two before `Close`).

**Changes.**
- 2026-10-19, I5 (ADR 0029 (4)): the one question is named as the code asks it, `fsplan`'s `FirstCover`;
  `decide.Unenforced`, a wrapper over it that only tests called, moved into decide's test files.
- 2026-09-29, I8: restated for the child stage, the one caller of `landlock_restrict_self`, which now runs the cross-check.
- 2026-09-28, I5 (ADR 0028 S1): kept as a runtime assertion over the decision core's one containment question.

## 9. Conventions and best practices

Naming: `handle` unexported, constructor `New`; internal types stay unexported — only `enforce.Backend`/
`Handle` are public surface (REPO-LAYOUT.md). Errors: one sentinel per failure class
(`ErrLandlockUnsupported`, `ErrPathVanished`, `ErrRulesetBuild`), wrapped with `%w` — callers need `errors.Is`
for exit-code selection. Logging: none of its own — the caller renders `file:line: message [code]`; this
package just returns enough context. Context: only `Prepare` takes one; everything else is synchronous
in-memory, no goroutines. Resource lifetimes: one owner, one release path per fd (`handle.open`/`Close`);
never `dup`'d internally. The fd set's numbers are process-wide, so nothing outside it may close them, test
code included; a test that hands the ruleset fd to a child hands a dup, as the launcher does. I12
is the check for when that is broken anyway, on the held numbers and the ruleset's, and names the reuse it
cannot see. Testability (new): the real Landlock syscalls sit behind the unexported
`landlockSyscalls` interface injected via `Options` (§2/§4), never called directly from rule-building logic,
so every rule computed by R2–R22 is unit-testable with no root and no real kernel. Fuzzing: the sibling
walker (R3) against adversarial trees, the write-flag mask test (R12) against the full `uint32` space
(ARCHITECTURE §7 fuzz-target list). Benchmarks: `Prepare` wall time vs. entry count in `test/e2e/overhead`
(no budget row yet, §11). Doc comments: every exported identifier states its ABI/kernel precondition inline.

## 10. Tests

**Unit** (no root, fake syscalls behind `Options.syscalls`, §2/§4/§9): sibling enumeration (R3) — depth 1/10,
0/1000 siblings, symlinked ancestor, overlapping targets (E7), nested and duplicate targets plus a hardlinked
target (E29/I11), inode aliases of deny nodes (E32: a write entry that is a target's hardlink or an ancestor's
bind mount, a target an `fs.watch`/implicit entry held first, an exec/`unix:` grant on a target's inode with the
reason each gives and the `unix:` one preparing below ABI 9, a level that is a target's inode with a second
target one, two and three levels beneath it, two levels that are one directory), target at `/` (E5, pre-rejection), concurrent-rename simulation (E28), a target under a `0111` ancestor (E33); unenforced-under-writable-parent (R4) across every relative position of a write/ask
and a deny_read entry; ABI degrade table (R2) — one case per ABI 1–11, clamp beyond 11 (E25); exec grants (R5)
— binary, directory, script with allowed/disallowed interpreter, MCP command, agent command, shadowed
basename (E16), `#!` coverage asked of resolved paths (a symlinked `exec.allow` directory, a symlink out of
one, an absolute `#!` sharing only a basename with a grant), a synthesised ELF whose `PT_INTERP` names a
denied path, a write entry, a directory or a hardlink of a target (E29); net/unix rule construction
(R6/R21/R22) — port dedup, empty `net.allow`, ABI bands
1–3/4–8/9/≥10, abstract vs. pathname `unix:` entries; filter assembly (R9–R13) — golden `[]bpf.Instruction`
dumps per arch, exact `AUDIT_ARCH_*`/syscall numbers/`0x243` offsets, absence of a flag test on the always-
notified syscalls, plus a `record: full` golden set (R16); the ABI-conditional truncation arms (E31) — one
case per ABI band and per open shape on both arches, and `Prepare` threading the *probed* ABI into the
filter — and the `IPPROTO_MPTCP` `socket(2)` arm (E30) at every ABI and record mode; `Capabilities()` reporting (R19/I10) — one
assertion per ABI band; the child stage's `sys.RestrictSelf` (R18, sys's `TestRestrictSelfFallbackAndNoNewPrivs`) —
fake `-EINVAL` forces the fallback, fake success skips the second syscall, a refused `LOG_*` flag fails; `Close` idempotency (I7); fd-exhaustion (E11)
closing every prior fd exactly once; a held number, or the ruleset's, that another owner closed or reopened
before a path rule went in (the ruleset's also before a net rule, and after the last rule), which fails the
build and is not closed again; a held number whose identity `statx` cannot give, which fails the build
without being disowned and is closed at cleanup only once it names its own file again; and a held or
ruleset number reopened after `Prepare` returned, which `Close` reports and leaves open; the ruleset's number
reopened on a pipe and on an `O_PATH` file, which the probe answers `EBADFD` and `EBADF`, with the fake's
probe held to the same answers as the kernel's (I12).

**Integration** (`//go:build integration`, root/userns, real kernel, `test/vm`): `Prepare` against a real
filesystem, ABI cross-checked against `doctor`'s independent probe; end-to-end fork+`landlock_restrict_self`+`execve` of
a test binary attempting a denied/allowed write, a denied/allowed-sibling read, an unlisted/listed exec, a TCP
connect with `net.allow` empty vs. non-empty at ABI ≥ 4 vs. < 4 (E4), a connect to a declared host on an
undeclared port (R6), a `unix:` connect below/above ABI 9 (R21: `TestIntegrationUnixConnect`), a UDP send to an undeclared port
at ABI ≥ 10 (R22: `TestIntegrationUDPPorts`), a signal outside the domain at ABI ≥ 6 (R7); a `truncate(2)` and an `O_RDONLY|O_TRUNC` and `O_ACCMODE|O_TRUNC` open
under the ABI-2 filter, with the ABI-3 filter as the control that lets the same call through (E31), and a
`socket(_, _, IPPROTO_MPTCP)` refusal beside a classic TCP socket that still opens (E30) — both install a
real seccomp filter and need no root, but the Landlock half of E31 (a 6.1 kernel allowing the control call)
is only reproducible on the AL2023 row of the matrix; across the kernel matrix (ARCHITECTURE §14: Ubuntu 24.04
ABI 4, AL2023 ABI 2, RHEL 9 ABI 6, Debian 13 ABI 6); E11/E27 reproduced with a lowered `RLIMIT_NOFILE` shared
with a fake ledger-writer fd opener; a sibling unlinked between its open and its rule, which prepares (E28);
a sibling's number reopened on the `deny_read` target before its rule, which fails the build (I12); the
empty-rule probe's answers, for an `O_PATH` file too, and the ruleset's number reopened on a pipe and on an
`O_PATH` file, before a sibling's rule and before `Close`, each left open (I12); the helper that runs the ruleset in a child leaves the Handle's fd
alone, with an unrelated file standing at the freed number while the finalizers run.

**E2E**: no standalone kill test — exercised inside kill test 1 ("one write refused") and kill test 6's
tier-1 leg (P0-DESIGN §12).

## 11. Open questions

- `Handle` (`docs/P0-DESIGN.md` §2.6) has no ABI accessor, so the child stage cannot directly learn the probed
  ABI for the child stage's flag choice (R18) — resolved here with a flag-then-fallback pattern needing no new
  interface method.
- *Resolved (2026-09-22):* the mechanism for `gap what=enforce why=landlock-topology` (ARCHITECTURE
  §4.1(6)) is the notify list, not an `argv[0]` match: `mount`, `umount2`, `pivot_root` and `move_mount` are
  notified (R11) and the supervisor refuses and records each one (supervisor R31). An `argv[0]` list would name
  a sandbox that never mounts and miss one under another name; the syscall is what the domain refuses. The
  closed list survives as `compile`'s `landlock-topology` warning (agent-contract §7).
- E18 (loader resolution unreachable through directory-only `exec.allow` grants): pre-scan every loader in a
  granted directory (cost scales with size) or document the refusal as a contract-authoring gotcha — open.
- No `Prepare` performance budget row exists in `docs/P0-DESIGN.md` §9; E22's linear scaling could make
  `tego run` startup latency user-visible on a large contract — no row yet.
- Whether `fs.watch` paths need their own `O_PATH` fd is unresolved: SEMANTICS treats `watch` as recording-only
  (§7); `kindWatch` may be an unnecessary fd-budget line item.
- E27's cross-component `RLIMIT_NOFILE` budget: no reservation or ordering guarantee exists between this
  package's fd usage and the ledger writer's/`cgroup` package's, in the same launcher process, left to `internal/runtime.Run`'s wiring.

## Corrections to earlier text

**C1.** The prior R6 stated "Landlock's TCP rule type carries no port field
below ABI 10," following ARCHITECTURE.md §7 / SEMANTICS.md §5's "no port rules." This is contradicted by
`struct landlock_net_port_attr{allowed_access, port}` in `uapi/linux/landlock.h` since ABI 4/kernel 6.7 (the
ABI that introduced `CONNECT_TCP`/`BIND_TCP`; ABI 10 added UDP, not TCP granularity), and by ARCHITECTURE.md
§2 ("TCP by port (ABI 4+)"), §14 ("tier 1 (fs + TCP port)"), and CAPABILITIES.md row 13 ("declared TCP ports
only"). With the normative documents disagreeing among themselves and one side independently falsified by the
kernel's own uapi header, this spec follows §2/§14/CAPABILITIES.md (now R6) and flags §7/SEMANTICS §5's
wording as needing a doc fix upstream. The same reasoning extends, as additions, to R21 (`unix:`, ABI ≥ 9, SEMANTICS §5 / CAPABILITIES.md's "unix sockets" row) and R22 (UDP,
ABI ≥ 10, same two documents) — both foreclosed by the prior R2's blanket "ABI 8–10: not implemented," narrowed
here to ABI 8 (TSYNC) only.

**C2.** `func New() enforce.Backend` → `func New(opts Options) enforce.Backend`,
matching REPO-LAYOUT.md's own illustrative signature for this package (line 149) and supplying the
fake-syscall injection seam §10's unit tests require.

**C3.** The child install-failure row in §7 moves from exit 126
(`run_end reason=exec-failed`) to exit 125 (ledger: none), matching RUN-IDENTITY.md: 126 is "the command was
found but could not be executed" (the *target* command), 125 is "Tego failed before exec: ... program-load
error" — the correct bucket for a kernel-object install failure that never reaches the target's own exec.


**C4 (2026-09-22).** Three changes, each fail-closed or a record that was missing. (a)
`RESOLVE_UNIX` is handled only under a `net:` section (R2's ABI-9 row, R6, R21): with none, the agent's own
connect to a pathname socket outside a write entry was refused at ABI ≥ 9 while SEMANTICS §1, the supervisor and
`Evaluate` all said "deny nothing", and the same contract reached the socket below ABI 9. (b) x86-64's `rmdir` joins
the notify set (R11): a directory removed through it had no line in any tier, the observe run included, which the
supervisor now records as it records `unlinkat(AT_REMOVEDIR)`. (c) `open_by_handle_at` joins R10's `ENOSYS` set:
an open no line can name is refused rather than left unrecorded.

**C5 (2026-09-23).** E11 and the §7 row say the fd-exhaustion exit names the count
of descriptors held. Running out while reopening a directory to list it (E27's enumeration) was wrapped as
`ErrFDExhausted` but named no count; it now does, as an entry's own open does, and
`TestPrepareFDExhaustion` checks the count is named whichever of the two ran out.

**C6 (2026-09-23).** Fail-closed addition. §7 gains the "held descriptor lost" row, §8 gains I12, and E28
now names both windows in which a sibling can vanish. Found as a `landlock_add_rule(deny_read sibling …): bad file
descriptor` under a full-suite load. Its cause was test code. The integration helper wrapped the Handle's
ruleset fd in an `*os.File`, whose finalizer closed that number again during a later `Prepare`, on a number the
builder then held. The kernel takes a path rule by number, so a number reused that way puts another file's
inode in the ruleset with the entry's rights. Before C6 the spec assumed one owner and checked nothing, which
the fd set's own code cannot guarantee for the whole launcher process. The ruleset number is checked as well,
by the empty-rule probe, since an unconditional close of it on a failed build or at `Close` was the same
fault on the ruleset's side; and a held number whose `statx` fails other than `EBADF` is reported as of
unknown identity, not as lost. The
probe answers `EBADF`, not `EBADFD`, for an `O_PATH` file at the ruleset number (`fdget` does not see
`O_PATH` files), where I12, the §7 row and the error had said `EBADF` meant closed. They now say closed or
`O_PATH`. The behaviour did not change: the number was already left open on `EBADF`, which is fail-closed.

**C7 (2026-10-03, recorded 2026-10-05 as ADR 0040).** Fail-closed addition, R5a. A nonempty built-in
`RuleTable.DenyWrite` makes `Prepare` fail with `ErrNegativeWriteNeedsPlane` before any rule is built, and
`enforce.Select` refuses the contract at tier landlock, and at tier cgroup without a plane mode, before launch (exit
125, `tier-unavailable`). Before it, this tier ran such a contract and left the targets to the supervisor's
pathname refusal (supervisor R15c), which SEMANTICS §2 called "best effort, not a closure": a sibling thread or a
symlink swap between the supervisor's read and the kernel's lookup landed the write in a target. ADR 0040 records it, its cost to users without a
plane (a write entry that contains a repository's `.git` no longer runs here) and the rejected options. Tests:
`TestProtectedWritesRequirePlaneBeforeAnyRuleIsBuilt`, `TestSelectProtectedWritesRequiresActualPlane`.

**C8 (2026-10-05, ADR 0041 D1 (a)).** R5a's refusal is opted into, no longer the default. ADR
0041's D1 decided (a): a table with built-in `deny_write` targets is prepared and run at this
tier, and on tier cgroup's listener, with the supervisor's best-effort refusal (supervisor R15c) as before C7, disclosed per
target at compile and as run_start `best_effort` `deny_write/default`; a contract that says `fs.assurance: kernel`
keeps C7's refusal, its error naming the key. ADR 0040 (1) is superseded in that part. Tests: C7's two now set
`fs.assurance: kernel`; `TestProtectedWritesBestEffortByDefault`, `TestSelectProtectedWritesBestEffortByDefault` and
`TestIntegrationDenyWriteBestEffortAtLandlock` hold the default.

