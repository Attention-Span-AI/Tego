# ADR 0041: a supervisor decision on copied arguments is completed in the run's own kernel context, refused, or disclosed; it is never silently CONTINUEd

Status: **accepted 2026-10-05**, D1 decided **(a)** (the 2026-10-05 note near the end); Stage A Steps 1, 3, 4, 5 and 6 built 2026-10-05, Step 2 built 2026-10-05 and measured 2026-10-16, Step 5's capability rows and `compile --test` columns 2026-10-16; Stage B built 2026-10-16 as the contract opt-in `gate.completion: held`, and its open faults (its held opens held to the kernel's own answers over 395 open shapes, two fail-closed divergences named) closed 2026-10-17, and later fixes refusing a held open of the open deputy's own thread group's `/proc` tree (its leader's `/proc/<tgid>` and every thread's `/proc/<tid>`), by name, through a descriptor or on any procfs mount, a third fail-closed divergence; its budget missed (TARGET-MISS: 2.01× the gated path on the host, 2.83× and the root tiers' 4.14× in KVM), the default unchanged; D2's LSM label check not built (a disclosed residual); its bind-mount and overlay spaces held to the kernel's answers by the differential suite as root, the conformance suite's own fixtures for them waiting on ADR 0017 space (5) (§Implementation notes). Supersedes ADR 0040 (1). Amends ADR 0007 (where a gate verdict is completed) and ADR 0008 (where a held open is completed). Records the `deny_write` launch rule of ADR 0016/0024 as stated in agent-contract R20, enforce-landlock R5a, supervisor R15c and SEMANTICS §2.
Amended in part by ADR 0048 (accepted 2026-10-06): D1 gains the command-rule rows (`exec.rules/argv`, disclosed (D) at every tier until P2's pins); with pins, the `gate.exec` row's argv and names leave `best_effort` at C+ and B.
Amended in part by ADR 0047 (accepted 2026-10-20): a mutation in an `fs.ask` scope is completed by the supervisor on pinned names (the deputy holds no right there); a gated mutation in the ask range inside one write entry is to be completed by the open deputy (decided, not built: it stays (R) `completion_unsupported`); rejected option 14 no longer covers `fs.ask` scopes.
Amended in part by ADR 0044 (accepted 2026-10-16, not built): a fourth outcome, (V) verified before the first instruction, for an approved exec (`exec.ask`, `exec.unlisted: ask`, the gate's exec ask range) at every tier.

Revised 2026-10-05. Claims of an earlier text that did not hold up are withdrawn: held-fd
completion "+15–25 µs", a CONTINUE fall-through for non-regular objects, a relay keyed on the copied address
family, plane cells for gate mutations, a per-tgid umask cache, a held-fd upgrade for `deny_write` write-opens,
and a best-effort `deny_write` default presented as decided.

## Context

The tier-1 supervisor reaches a verdict on **copied** syscall arguments: a pathname read with
`process_vm_readv`, a `sockaddr` read the same way, an `argv` vector. For most actions it then answers
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`, which hands the syscall back to the kernel, and the kernel copies and
resolves the argument **again**. Between the two copies, a sibling thread or `CLONE_VM` child in the agent's
address space can rewrite the bytes. This is the documented seccomp_unotify TOCTOU (ADR 0008). Any security
decision taken on the copied bytes and expressed as `CONTINUE` is therefore advisory. A *refusal* on copied
bytes is honest: the syscall never runs. An *allow* that is continued is not a decision about what the kernel
will do.

ADR 0008 closed this for `ask`. An approved open is completed with `ADDFD|SEND` of a descriptor the supervisor
opened on the **held** inode. An approved connect is performed on a `pidfd_getfd` **duplicate** of the agent's
socket. A later series of commits added two new kinds of supervisor decision on copied arguments that
are answered `CONTINUE`:

- **Scored gate rules** (docs/p0/gate.md, ADR 0007). `gateFS` scores a copied or walked pathname, and `answerFS`
  answers `CONTINUE` whenever the gate does not refuse. `gateNet` and `handleConnect` score a copied `sockaddr`
  and answer `CONTINUE` for a `continued` destination (a contract with no `net:` section). A Fast-Open stream
  send does the same (`send.go`). `gateOpen` takes ADR 0008's held path, for read-opens and write-opens alike
  (`TestGateReadActualAtomicCompletionAfterSymlinkChanges`), but only when the **copied** name already scored
  `ask`. The `isWriteOpen` restriction belongs to `askOpen` (scoped `fs.ask`), not to the gate.
  - An unprivileged reproduction has a sibling thread racing past
    an `fs.read`/`fs.write` gate and past a `net to <ip:port>` gate under a contract with no `net:` section. About
    18–25 % of attempts succeed per try, so retries make the bypass certain, and the ledger names the benign
    name or destination.
  - `gateFS` scores the lexical spelling as **complete** facts when the
    supervisor's own walk failed with a non-lookup errno (EMFILE, ENFILE, ENOMEM, EIO, EXDEV). This contradicts
    gate.md R1 ("missing relevant facts refuse as unreadable").
  - The chmod family is not notified under a write gate at `record: summary/off`.
  - `fs.read matches` is bypassed **deterministically** through
    `link`/`rename`: `gateFS` scores `FSRename`/`FSLink` with `fs.write` predicates only.
- **A supervisor-decided `deny_write` became launch-fatal without a plane** (2026-10-03).
  - The built-in set (agent-contract R20) is compile-built; the user never writes it, and the schema has no
    user-declared `fs.deny_write`. It is non-empty for the common coding-agent contract: `fs.write: ["./"]`
    inside a git repo yields `.git/hooks`, `.git/config`, `.claude`, `.bashrc` and similar targets.
  - `Select`, `Prepare` and `choosePlane` now refuse that run at tier landlock and at tier cgroup without a
    plane. Tier landlock is the only tier an unprivileged user can get, and the only one on a host without BPF
    LSM.
  - `tego compile` only warns (exit 0) while `tego run` exits 125.
  - Until then these contracts ran best-effort with an `unenforced` warning. A different answer was
    already on record, option (b), the `deny_write` opt-out: the default stays refused, and a contract opts out with
    a recorded `fs.deny_write: []`.

Today the supervisor completes some actions race-free and not others. The table below says which:

| Action | Race-free completion exists? | Mechanism and limits |
| --- | --- | --- |
| open (any object) | only for `ask`, and **outside** the run's kernel context | ADR 0008 `ask_open`: pin the inode, then `ADDFD\|SEND`. The supervisor thread that opens it has no Landlock domain, sits outside the run cgroup and carries tego's LSM label (D2) |
| non-open fs mutation (unlink, rename, link, symlink, mkdir, mknod, truncate) | no | the plane's `path_*` hooks decide the contract floor and `deny_write` rows only, never a gate predicate |
| chmod family | no | `path_chmod` covers `deny_write` targets only (enforce-plane R12) |
| connect on an IP socket | yes | relay on the `pidfd_getfd` duplicate, with tego's credentials (only under a `net:` section or a `models[]` guard today) |
| unix connect | yes, under a `net:` section | `relayUnix`, with the task's credentials (R11) |
| addressed Fast-Open stream send, IP | yes | relay on the duplicate (R12) |
| addressed IP datagram (`sendto`/`sendmsg`) | yes | `relayDatagram`, from the immutable copy |
| addressed datagram **batch** (`sendmmsg`) | no | I3: the kernel writes per-message counts back into the agent's array |
| addressed **unix** datagram | no | must not be relayed (tego's credentials and cwd) |
| exec: image | no, for the gate | `bprm_check` decides the contract's exec rows, not the gate's `exec matches` |
| exec: argv | no, at any tier | the kernel re-reads argv after any decision |

## Decision

### Principle

Every **cell** (rule kind × action × tier) has exactly one of three outcomes. The cells are in D1.

- **(A) Completed race-free.** The supervisor never answers `CONTINUE`. The action is performed on what was
  scored: the held object for opens, the duplicate socket with the copied address for connects and sends. The
  completion runs in the run's own kernel context, so it is never more permissive than the kernel path would
  have been (D2, D3).
- **(R) Refused.** The supervisor answers a documented errno and records the reason.
- **(D) Disclosed best-effort.** The supervisor decides on copied facts, refuses early on a copied-name hit, and
  answers `CONTINUE` otherwise. Such a cell is never counted as enforced. Compile names it, run_start records it,
  and status and drift show it (D7).

Four rules bind the outcomes:

1. **CONTINUE is permitted only in two cases.**
   - The supervisor made no decision that narrows or escalates. Examples: an open whose gate kind cannot reach a
     score above `allow` (`MayEscalate(kind)` false), or a record-only notification.
   - The cell is (D).
2. **Every failure inside an (A) cell fails closed.**
   - Whether a syscall takes the (A) path is decided statically from the compiled policy: does this gate kind
     escalate? It never depends on the copied bytes.
   - Once on that path, every outcome is one of: completion, the lookup's own errno, or (R). It is never
     `CONTINUE`.
   - If the copied name chose the branch (regular or not, present or not), a sibling could choose `CONTINUE`
     and re-open the race. This is why a `CONTINUE` fall-through is withdrawn.
3. **Never exceed the kernel.**
   - An (A) open is performed by a deputy that is inside the run (D2).
   - The supervisor still applies every userspace floor check that `gateOpen` applies today (D3), as defence in
     depth.
   - It delivers only the object it scored, verified by `(dev, ino)`.
4. **Disclosure is static and recorded.** A (D) cell is a property of the compiled contract at the selected
   tier. It is shown in compile output and in run_start, not in a per-run `gap` line. `gap` stays for events
   that happened (D7).

### D1 — completion table (rule × action × tier)

Tiers:
- **L** = landlock (tier 1, unprivileged, no plane).
- **C⊘** = cgroup without a plane (listener fallback).
- **C+** = cgroup with an `lsm`/`fmod_ret` plane.
- **B** = bpflsm.

"Stage A" ships now. "Stage B" ships only after the deputy prototype meets the D2 and §Performance budgets.
Until then, Stage B cells are (D).

| Rule → action | L | C⊘ | C+ | B |
| --- | --- | --- | --- | --- |
| gate `fs.read matches` → read-open, escalating kind | (D) → **(A) Stage B**, per object class (D4) | same | same | same |
| gate `fs.write outside worktree` → write-open, escalating kind | (D) → **(A) Stage B**, per D4 | same | same | same |
| gate fs kind with `MayEscalate` false → open | CONTINUE (no decision) | same | same | same |
| gate `fs.write …` → non-open mutation (unlink/rename/link/symlink/mkdir/mknod/truncate) | (D) | (D) | (D): the plane carries no gate rule | (D) |
| gate `fs.write …` → chmod family | (D), notified after Step 2 | (D) | (D) | (D) |
| gate `fs.write …` → xattr and chown families (a POSIX ACL set included) | (D), notified from 2026-10-16 | (D) | (D) | (D) |
| gate `fs.write …` → timestamps (`utimensat` and the older forms) | no decision: never notified (rejected for cost, and no permission changes) | same | same | same |
| gate `fs.read matches` → **source** of rename/link | (D) after Step 4 (scored today with write predicates only: a deterministic bypass) | same | same | same |
| gate `exec matches` → exec (image **and** argv) | (D) copied facts | (D) | (D): `bprm_check` decides the contract's exec rows, not the gate | (D) |
| gate `exec matches` → score in the ask range | (R) unsupported-completion refusal (built) | same | same | same |
| gate `net …` → connect on an **IP-domain** socket (SO_DOMAIN), any spelled family | **(A)** relay on the duplicate with the immutable copy (Step 3) | same | same | same |
| gate `net …` → Fast-Open stream send, IP-domain socket | **(A)** relay | same | same | same |
| gate `net …` → addressed datagram, IP-domain socket | **(A)** `relayDatagram` | same | same | same |
| gate `net …` → addressed datagram batch, IP-domain socket | (R) ENOSYS; glibc set to `single-request` for any net gate | same | same | same |
| gate `net …` → relayed IP socket carrying a source-route option (`IP_OPTIONS` SSRR/LSRR, `IPV6_RTHDR`) | (R) `relay-source-routed` (Step 3) for a socket that carried the route before the filter; (R) filter `EPERM` on the `setsockopt` that would add one (enforce-landlock R11b; amended 2026-10-05) | same | same | same |
| gate `net undeclared` → unix connect | (A) `relayUnix` under a `net:` section; (D) with no `net:` section | same | same | same |
| gate `net undeclared` → addressed unix datagram | (D), never relayed | same | same | same |
| gate `net to host:port` → any unix destination | no decision: a literal `host:port` never matches a unix name, so CONTINUE carries none | same | same | same |
| built-in `deny_write` → write-open of a target | **D1** (§D8): refuse launch, or (D) by recorded opt-out | same | (A) plane | (A) plane |
| built-in `deny_write` → mutation or chmod of a target | same as the row above | same | (A) plane | (A) plane |
| `deny_read` move (R15d) → link/rename out of a nested `deny_read` | n/a (tier 1 enforces no read) | (D) | (A) plane | (A) plane |

Notes that make the table exact:

- **Name, not inode.** `fs.read matches` and `fs.write outside worktree` are **name** predicates. A second name
  for the scored file is scored under *that* name: a hard link made before the run, a rename made earlier
  (itself a (D) mutation), or a case-fold alias. (A) closes the **swap** race, because the kernel acts on the
  inode that was scored. It does not make a name glob a boundary. gate.md states this as a predicate residual,
  not a TOCTOU.
- **Non-open mutations are (D) at every tier, gates included.** The plane decides the contract floor and the
  `deny_write`/`deny_read` rows on the resolved object. It never decides a gate predicate (ADR 0007; rejected
  option 9). Non-open mutations are not (D) because a race-free completion is impossible. The deputy of D2 could
  perform them on a pinned parent with the copied leaf name (the connect-relay analogue that the "hold
  or refuse gated mutations" describes). Such an emulation of rename, link, unlink, symlink, mkdir, mknod, chmod
  and truncate is rejected **for cost and semantics now** (rejected option 14), not as impossible.
- **The exec gate is (D) at every tier, image included.** No mechanism re-reads argv race-free, and the plane's
  exec rows are the contract's, not the gate's. R22a already says the argv match is a notification-time
  snapshot.

### D2 — where a held completion runs: an in-run open deputy

**Requirement.** An (A) open is performed with the requesting task's full kernel context:
- The same Landlock domain;
- The same cgroup, so the plane's `tego_current_run` matches and fanotify's in-run test applies;
- The same credentials, namespaces and LSM label.

The delivered file then carries what the kernel path's file would carry: the domain's `TRUNCATE` and
`IOCTL_DEV` rights, and plane and fanotify decisions taken in the kernel. The userspace rechecks of D3 stay as
defence in depth. They are never the only floor.

**Mechanism (decided; Stage B prototypes it).** An **open deputy** process belongs to the run:
- **Start.** The child stub (`launch.ChildMain`) starts it after `landlock_restrict_self` and after cgroup
  placement, and before it installs the run's listener filter. The deputy is the tego binary re-executed as
  `__open-deputy`, so it shares the run's domain rather than a sibling domain built from the same ruleset.
- **Exec grant.** Starting it needs one **runtime exec grant** on the tego binary's inode: a Landlock execute
  rule, plus a plane exec row at B. The grant is shown in the effective policy like the other runtime rules
  (`agent.IsRuntimeRule`). If the agent execs the binary itself, it gets an inert copy with no supervisor
  channel.
- **Confinement.** The deputy sets `PR_SET_DUMPABLE 0`, so the agent cannot ptrace it without
  `CAP_SYS_PTRACE`. It installs its own allowlist seccomp filter (kill on anything outside walk, open, fstat,
  readlink, umask, `recvmsg`/`sendmsg` and exit). It talks only over a socketpair inherited from the stub.
- **Work.** It walks as the task. That reuses `walkExec`/`walkCreate`, which start from `/proc/<tid>/root` and
  cwd/dirfd; the deputy reads those with the run's own ptrace rights. It pins `O_PATH`, opens with the task's
  flags, and returns descriptors with `SCM_RIGHTS`.
- **Delivery.** The supervisor scores and checks (D3), verifies the returned descriptor's `(dev, ino)` against
  the scored pin, and delivers it with `ADDFD|SEND`.
- **ADR 0008 completions move too.** Human-approved `ask`/gate-ask opens move to the deputy in Stage B. Until
  then they keep today's supervisor-thread completion, which is the residual named in §Consequences.

What the deputy does not share with the task, and the answer for each:
- **pid and session.** These matter for per-opener objects; D4 lists them, and they are refused or
  special-cased.
- **The agent's later changes.** A later `setsid`, `unshare`, or a credential change at a root tier is compared
  for each object class that depends on it. A mismatch is (R).
- **An LSM label taken by an exec transition** (AppArmor or SELinux confining the agent's binary). The deputy
  compares `/proc/<tid>/attr/current` with its own label when the host has a task-labelling LSM active. A
  mismatch is (R) `held-label-differs`. The prototype measures this read and may replace it only with a sound
  cheaper key.

Why not a supervisor thread (rejected options 5 and 6):
- **Cgroup.** A cgroup v2 domain cgroup holds whole processes. A launcher thread cannot be in the run cgroup
  without making the run cgroup threaded, and the memory controller forbids that.
- **Plane and fanotify.** So the plane returns 0 for such a thread (enforce-plane non-goals:
  `bpf_get_current_cgroup_id()` is not in `tego_run_set`), and fanotify allows it as an opener outside the run
  (`cgroup/fanotify.go`, R8).
- **Landlock scoping.** A thread restricted with the run's ruleset gets a *sibling* domain. Landlock's ptrace
  scoping then refuses it the agent's `/proc/<pid>/maps`, `environ` and `mem`, which glibc's
  `pthread_getattr_np` reads.
- **The alternative turns kernel refusals into allows.** Reproducing the plane's inode rows, its nearest-wins
  ancestry walk, Landlock and the host LSM in userspace is exactly that substitution.

### D3 — what the supervisor checks before it delivers

The order of checks for an open on the (A) path:

1. **The copied name.** A refusal on the copied name is final: the syscall never runs. Today's `gateFS` floor
   and protected-path guards answer first.
2. **The deputy's pin.** If the deputy's walk fails, the answer is the walk's own errno (D4).
3. **The floor checks on `h.resolved`**, exactly as `gateOpen`/`askOpen` apply them today:
   - The unconditional protected-path guards;
   - The contract floor: `fsVerdictIn` must return `Allow`, and anything else refuses;
   - `deny_read` (`decide.NearestIn(...).DenyRead`);
   - for a write-open, `DenyWriteTarget` and `AskDenyWriteTarget`;
   - for a scoped `fs.ask`, `askScopeValid`.

   The open is delivered only when the floor allows. A gate score can never grant what the floor refuses
   (gate.md R1).
4. **The gate, scored on `h.resolved`.** The verdict is the larger of the copied and the held scores, as
   `gateOpen` does today, so a symlink spelling cannot lower a score.
   - Up to `allow`: the deputy opens.
   - The ask range: human approval (ADR 0008), then the deputy opens.
   - The refused range: `EACCES` (authority `gate`).
5. **The deputy opens in the run.** The kernel's Landlock, plane, fanotify and DAC decisions apply to this open.
   A kernel refusal reaches the agent as the kernel's errno.
6. **Identity.** `(dev, ino)` of the returned descriptor must equal the pin; for a create, the parent pin plus
   the leaf. Then `ADDFD|SEND`.

### D4 — object classes on the (A) path

This applies when `MayEscalate(kind)` holds for the open's kind. Every row is decided by the **held** object,
never by the copied name.

| Object reached | Outcome |
| --- | --- |
| existing regular file | (A) deputy open |
| absent leaf with `O_CREAT` | (A) deputy `openat(parent_pin, leaf, flags\|O_NOFOLLOW)`. `O_EXCL` is added only when the agent asked for it or a human approved the absent leaf (ADR 0008 keeps that). `EEXIST`/`ELOOP` from a leaf that appeared meanwhile triggers one re-pin and re-score, then the errno |
| `O_TMPFILE` | (A) deputy `openat(dir_pin, ".", flags)`; scored on the directory |
| directory (`O_DIRECTORY`, `opendir`, `O_RDONLY` on a directory) | (A) deputy reopen. A write-open gets the kernel's `EISDIR` from the deputy's own open |
| `O_PATH` | (A) deliver the deputy's pin. `O_NOFOLLOW` pins a final symlink itself |
| final symlink with `O_NOFOLLOW`, not `O_PATH` | the walk's `ELOOP` |
| FIFO | (A) deputy open on the blocking path. It is counted against the relay ceiling with R21's standby backfill, and blocks as the kernel's open would |
| socket inode | the deputy's open returns `ENXIO`, the kernel's answer |
| char device, mem class 1:3/5/7/8/9 (`null`, `zero`, `full`, `random`, `urandom`) | (A) deputy open |
| tty class (major 4, 5:0 `/dev/tty`, 5:2 `/dev/ptmx`, 136–143 pts) | (A) with `O_NOCTTY` forced. (R) when the agent's call lacks `O_NOCTTY` and the task is a session leader with no controlling tty, the one case where the kernel's open would acquire one. For 5:0, also (R) unless the task's `tty_nr` equals the deputy's. One `/proc/<tid>/stat` read, tty class only |
| every other char or block device (for example `/dev/net/tun`, whose open uses the opener's netns) | (R) `EACCES`, reason `held-unsupported` |
| `/proc/<pid>/…` for a pid in the run other than the deputy's own, `self` translated by the walk | (A) deputy open: same domain and credentials, so `ptrace_may_access` answers as it does for the agent. A non-dumpable agent gets `EACCES` where its own thread group would pass, a documented fail-closed divergence |
| `/proc/<deputy-pid>/…` and `/proc/<deputy-tid>/…` — the open deputy's own thread group | (R) `EACCES`. The deputy runs the walk and the reopen itself, and a process always passes `ptrace_may_access` against its own thread group, so without a guard its own ptrace-gated entries (`mem`, `environ`, `auxv`, `maps`, `fd/N`, `cwd`, `root`, `exe`, `task/*/…`) would be delivered where the agent's own open is refused, the deputy being undumpable (`PR_SET_DUMPABLE 0`). Every pin refuses any lookup into the deputy's own `/proc/<tgid>` tree, or into the `/proc/<tid>` directory procfs keeps at its root for each of the deputy's other threads (a Go program always has several, and those directories have inodes of their own), with the agent's own errno, `EACCES` (`deputyProcDepth`; the numeric deputy pid is not what `self` translates to), the final component an `O_CREAT|O_EXCL` or trailing-slash `O_CREAT` pin names included, and so does a pin that ends inside the tree with no lookup there, through a magic link such as `/proc/self/fd/N` of an `O_PATH` descriptor a run process holds, or an `AT_EMPTY_PATH` descriptor (`landsInDeputyProc`). The tree is found on whatever procfs mount the pin crosses, a second instance or a bind mount of `/proc`, by asking whether the pid directory it hangs from has a `task/<n>` entry for `n` the deputy's tgid as that instance's own `self` names it (`proc_task_lookup` finds a thread id only within the directory's own thread group); a mount of part of a procfs, which the run cannot make, is refused as unsure. The plain world-readable entries (`status`, `stat`, `cmdline`) are refused too, a deliberate over-refusal: never more permissive than the agent's own, and the run has no business reaching the deputy through the gate. The deputy's `/proc/<tgid>` directory *itself*, and a thread's `/proc/<tid>`, reached with no further component, is (A), as the agent's own open of that listable directory is |
| `/proc/<pid>/…` outside the run | (A): the deputy's Landlock scope refuses it exactly as the agent's would |
| `/proc/sys/net/…` | (R) when `/proc/<tid>/ns/net` differs from the deputy's (the lookup uses the opener's netns); otherwise (A) |
| nameless object behind `/proc/self/fd/N` or `/dev/std*` (pipe, socket, anon inode, unlinked file) | (A) deputy reopen of `/proc/<tgid>/fd/N` |
| a linked object whose path is not visible in the supervisor's view (`errOtherView`, linked) | (R) `gate.unreadable`: the gate needs a name it cannot see |
| lookup failure (`ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG`, search `EACCES`) or `EFAULT` from the copy | the walk's or copy's own errno, never `CONTINUE` and never a blanket `EACCES` (ld.so, git and `which` probe missing paths constantly) |
| an errno that describes the task's state (`ADDFD`'s `EMFILE` from the task's full table; the in-run open's `ENOSPC`, `EROFS`, `EDQUOT`, `ETXTBSY`, `EACCES`) | that errno |
| tego-side failure (supervisor or deputy `EMFILE`/`ENOMEM`, deputy gone, held-open ceiling reached) | (R) `EACCES` with a recorded reason (`held-unavailable`, `held-limit`). It is never `CONTINUE`, and never the supervisor's own errno presented as the task's |

Step 1 applies the `errOtherView` split now, before Stage B. The gate treats a walk that reached a *nameless*
object as complete facts (no name can match). A walk that reached a linked object it cannot see, or that failed
with a non-lookup errno, is **incomplete** (`gate.unreadable`).

### D5 — semantics of a held completion

- **Flags.**
  - `O_TRUNC`, `O_APPEND`, `O_NONBLOCK`, `O_DIRECT`, `O_NOATIME` and `O_CLOEXEC` pass through to the deputy's
    open. `O_NOATIME` fails `EPERM` for a non-owner, as for the agent.
  - `O_NOFOLLOW` is honoured by the walk, not stripped.
  - The umask is read only for `O_CREAT` opens, from `/proc/<tid>/status` at that moment. It is applied with
    `umask(2)` in the deputy. The deputy's threads share one `fs_struct`, so `umask` plus `openat` for creates
    runs under a deputy-wide create lock. No per-call `unshare` is needed; a create stuck on FUSE or NFS holds
    that lock, but only other creates wait on it, and R21's ceiling bounds them. umask lives in `fs_struct`,
    which is shared per `CLONE_FS` group rather than per tgid, and it changes at runtime. No cache (rejected
    option 12).
- **Partial completion.** A create or truncate can happen and then go undelivered, because the notification was
  withdrawn or `ADDFD` failed. That writes E35's line (`operation_completed: true`, `fd_delivered: false`,
  `result_unknown` as applicable) and counts `orphaned`. `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (5.19+,
  already set where available) prevents a restart on a non-fatal signal. Below 5.19 a restart re-runs the open.
  A create without `O_EXCL` is idempotent. An agent `O_EXCL` gets `EEXIST`: E35's documented double side
  effect, recorded at build volume by the counter, not per line.
- **Ledger.**
  - A held allow up to `allow` is the **ordinary** fs action line: authority `rule`, path = `h.resolved`, gate
    fields with a new `gate_facts: held_object`. It is never the ask-style `emitApprovedGateAskOpen` line.
    `gate_facts: copied_syscall` is false once the held inode was scored (gate.go:27, compile.go:715,
    agent-contract R22a, gate.md R5, record README). The new value needs a record_minor bump and README text.
  - Human approvals keep `AuthorityHuman`. Gate refusals keep authority `gate`.
  - R7a and ADR 0016 (4): the supervisor writes the line for what it answers. At tier 2 the kernel recorder and
    the plane's record skip the deputy's tgid, so one action makes one line.

### D6 — net relay keyed on the socket's domain (Stage A)

An earlier text keyed the relay on the copied family (`d.isInet()`). A sibling then presents a unix-spelled
address on an AF_INET socket. `NetTo` scores a unix destination 0, so the connect is allowed and continued, and
the sibling flips the family word to AF_INET before the kernel reads it. A test reproduced this with a
fake kernel: an inet copy was relayed, and a unix-spelled copy still got `CONTINUE`. The rule is now:

- `resolveSocket` reads `SO_DOMAIN` of the duplicate when `c.guard != nil || Gate.Has(gate.Net)`, as it already
  does for the guard. A domain that cannot be read is taken as IP.
- On an IP-domain socket under a net gate, the connect, Fast-Open send or addressed datagram is **always
  relayed** on the duplicate with the copied raw `sockaddr`, whatever family it spells. A unix-spelled or
  wrong-family copy then gets the kernel's own `EAFNOSUPPORT`/`EINVAL` from the relayed call. AF_UNSPEC and
  unparsed families keep refusing as `gate.unreadable`. `refusesUndecidable` takes `guarded || ipGated`.
- The datagram decision uses `ipDomain`, never `d.isInet()`.
- On a unix-domain socket a sibling cannot reach an IP destination: the kernel refuses an AF_INET name there.
  Unix cells follow D1.
- **Source routes.** Before relaying, the supervisor reads `IP_OPTIONS` and `IPV6_RTHDR` on the duplicate. A
  socket with a source route (SSRR/LSRR, or an SRH that unprivileged code may set) is refused,
  `relay-source-routed`: its first hop is not the scored address. *Amended 2026-10-05:* that read
  alone is check-then-act, since the socket is shared with the agent's threads and `setsockopt` was not trapped: a
  sibling could add a route between the read and the relayed call. The filter of a run whose gate scores `net`
  therefore refuses `setsockopt(SOL_IP, IP_OPTIONS)` and `setsockopt(SOL_IPV6, IPV6_RTHDR / IPV6_2292RTHDR /
  IPV6_2292PKTOPTIONS)` with `EPERM` on the scalar level and option (enforce-landlock R11b), so no thread of the run
  adds a route, and the read decides a socket that carried one before the filter applied. Residual, disclosed: a
  process outside the run that shares the socket can still set a route at any time. *Amended 2026-11-02 (GAPS
  C34):* the arm and the read hold under every `net:` section too, where the relayed connect and every admitted
  datagram the supervisor continued followed a route to a first hop no entry admits; and under a `net:` section the
  supervisor refuses a datagram whose own control messages route it (`IP_RETOPTS`, `IPV6_RTHDR`), best effort
  (enforce-landlock R11b, supervisor R9 and R13b, SEMANTICS §5).
- **Prerequisite.** Supervisor-3 lands first: `RES_OPTIONS=single-request` for any net gate, not only for a
  guarded run. Otherwise any net gate breaks glibc `getaddrinfo` on the unaddressed batch on a connected UDP
  socket.
- **Blast radius**, stated in gate.md:
  - The run's whole IP egress moves into the relay regime: `relayCeiling` = Workers + 64 = 68 outstanding,
    beyond which a connect is `EACCES relay-limit`.
  - Non-local connects take the slow path (backfill, `ID_VALID` every 20 ms).
  - Ancillary data, `UDP_SEGMENT`/GSO, `MSG_ZEROCOPY` and datagrams over 64 KiB are refused (QUIC clients).
  - Host MAC LSMs mediate the relayed call under tego's label.
  - The plane has no LSM network hooks (enforce-plane non-goals). Tier 2/3 per-run `connect4/6` programs still
    decide on the socket's cgroup, which the duplicate keeps.
  - Compile warns when a contract with no `net:` section declares a net gate.

### D7 — disclosure

- **run_start.** A new field, `best_effort`, lists the stable ids of this run's (D) cells at the selected tier,
  for example `gate.fs.read/open`, `gate.fs.write/mutation`, `gate.exec`, `gate.net/unix-datagram` and
  `deny_write/opt-out`. It needs a record_minor bump, record README text and `RunStartPayload` agreement
  tests. `tego status` and `drift` show it. A Stage B cell drops out of the list once (A) ships.
- **Compile.** Compile prints one `unenforced` warning per id, `.only(tier)` where the cell is tier-specific.
  `compile --test` columns show the same.
- **Capability matrix.** New rows are appended per R23 (CAPABILITIES.md): `gate fs open completion`,
  `gate fs mutation`, `gate exec`, `gate net completion`, and `protected write targets` for `deny_write`. Existing
  rows are not reused. `fs.deny_write` (`CapFileWriteDeny`) is the row "deny file write outside contract",
  which concerns declared grants and must not flip with filesystem state.
- **No `gap what=enforce`.** spec/record/v1 defines `what=enforce` as the plane's counters of refusals already
  made, and a per-run `gap what=enforce why=deny-write-unraceable` is withdrawn. A (D) cell is
  a static fact, not an event. Events that happen, such as held-open tego-side failures, are counted in
  `run_end.supervisor` anomalies.

### D8 — the `deny_write` default at L and C⊘ (decision D1)

What holds under every option:
- At C+ and B the plane decides `deny_write` race-free, as today.
- Compile and run agree. At a pinned tier landlock (not build-capped) a refusing configuration is a compile
  `errorf`, mirroring the `setuid` case at compile.go:236. An auto contract that may land there gets a warning
  `.only(landlock)`. A run that refuses exits 125 with a fix naming the opt-out. This ends the compile and run disagreement.
- **No held-fd upgrade for `deny_write` write-opens** (rejected option 3). The supervisor's refusal of
  non-open mutations at the same tier is on copied names, so an adversary plants `.git/hooks/pre-commit` with a
  raced `rename(tmp, hook)` instead of a raced open. The upgrade buys no security there. It would make every
  write-open of the commonest contract pay the held cost, and the usability fix does not depend on it.
- **Hard links.** The supervisor's targets are names, so a hard-link alias of a target made earlier is not
  caught. The plane's rows are inode-keyed and do catch it. The supervisor's `deny_write` therefore never
  counts as enforced below the plane, whichever option is chosen.

| | (b) | **(b+) recommended** | (a) |
| --- | --- | --- | --- |
| absent `fs.deny_write` at L/C⊘ | launch refused (today) | launch refused (today) | runs; supervisor refuses copied-name hits |
| opt-out spelling | `fs.deny_write: []`: no protected targets | `fs.deny_write: []` as in (b), **plus** `fs.deny_write: best-effort`: keep the supervisor's early refusals of the built-in set, no enforcement claim | none needed; strict is opt-in through a top-level `assurance: kernel` |
| consent | recorded in the contract, `contract_hash` and run_start | same | none: a silent downgrade unless run_start records it |
| run_start / drift | `best_effort: [deny_write/opt-out]`, protected-writes row false | same, id `deny_write/best-effort` for the new value | `best_effort: [deny_write/default]` plus `deny_write: best-effort`; drift reports the lowered state |
| non-adversarial safety (an agent that just runs `git` or writes hooks) | lost with `[]` | kept by `best-effort` | kept |
| new surface | one tri-state field | one field: absent, `[]`, or `best-effort` | an assurance key (S2 below), merge rules, a schema entry |

Recommendation: **(b+)**. It keeps the recorded consent and today's fail-closed default. It adds the
value that keeps the cheap, honest early refusals that `[]` throws away. It touches the fewest tests, because the
default refusal and its tests stay and opt-out cases are added. Under (b) or (b+) no assurance key is needed for
`deny_write`.

If (a) is picked, the strict opt-in is specified now so it is not improvised later:
- **Shape.** One **top-level** `assurance: best-effort | kernel`, not `fs.assurance`, because it also governs
  `gate:` cells.
- **Effect.** `kernel` refuses launch for every rule whose cell at the selected tier is (D). By the table, that
  refuses every `fs.write` gate and every `exec` gate at **every** tier, which is by design: strict cannot be met
  for them.
- **Merge.** `extends` keeps the stricter value (merge.go:217's direction). A profile cannot silently weaken a
  parent.
- **Record and tooling.** run_start gets an `assurance` field and the record minor is bumped. The change also
  needs agent.schema.json, the schema/Go agreement test, print.go and CHANGELOG.
- **Compile.** Compile uses `errorf` at a pinned tier, deliberately unlike `net.assurance`'s `warnf` +
  `.only(tier)`, which is the compile/run disagreement above. `net.assurance` is left to its own fix.
- **No machine-config key.** None exists today, and this ADR adds none. An earlier claim that a machine config
  could flip the default was false.

### Reconciling with ADR 0007 and ADR 0008

- **ADR 0008.** "CONTINUE never carries a security decision" holds for every (A) cell. The (D) cells are named,
  recorded exceptions. Its completion executor moves from a supervisor thread into the in-run deputy (Stage B),
  which closes the residual that ADR 0008 completions run outside the run's kernel context.
- **ADR 0007.** "The gate only escalates, in the supervisor" is unchanged. Completion is (A) where D1 says so and
  disclosed elsewhere.
- Docs get dated notes, not rewrites (docs/adr/README.md editing policy).

## Consequences

**Security after Stage A.**
- The net gate's IP connect, Fast-Open and datagram races are closed by the SO_DOMAIN-keyed relay. This
  includes the family flip, which an earlier text missed.
- The walk-failure case is closed, with the `errOtherView` split.
- chmod is notified under a write gate, and from 2026-10-16 the xattr and chown families too (a POSIX ACL set is a
  mode change).
- The deterministic `link`/`rename` bypass of `fs.read matches` is closed: the source is scored with read
  predicates.

The fs open gate race is **not** closed in Stage A. Its cells are (D) and listed in
run_start and compile. "No supervisor CONTINUE carries a gate escalation" is therefore **not** claimed until
Stage B ships.

**Security after Stage B.**
- Escalating fs gate opens are (A) at every tier, and the completion never exceeds the kernel path, because the
  deputy is inside the run (D2).
- Human-approved opens gain the same confinement.

**Residuals at every stage:** name-not-inode predicates; non-open mutations and attribute changes (chmod, chown,
xattr) under a gate, and timestamps, which no gate scores; exec (image
and argv); unix datagrams; unix connects with no `net:` section under `net undeclared`; the hard-link alias for
`deny_write` below the plane; MAC-LSM mediation of relays under tego's label; the deputy's fail-closed
divergences (D4). Each is listed in run_start, compile and gate.md.

**TCB.**
- Today's ADR 0008 completion is a supervisor thread with tego's context. Its file carries no Landlock
  `TRUNCATE`/`IOCTL_DEV` restriction, and the userspace rechecks are its only floor. That is a residual until
  Stage B.
- Stage B adds the deputy (new code, but running with the run's own powers and an allowlist filter). It turns
  the userspace floor checks into defence in depth, and removes the per-call `RunAs` and `Unshare(CLONE_FS)`.
  That matters because container runtimes' default seccomp profiles deny unshare without `CAP_SYS_ADMIN`.

**Usability.** Depends on D1.
- Under (b)/(b+): today's default, plus a one-line recorded opt-out named in the refusal's fix text.
- Under (a): the git-worktree contract runs by default.
- In all options compile and run agree.
- A net gate now relays the run's IP egress (D6 blast radius).

**Availability.**
- Held opens use R21's standby backfill and a ceiling like relays: `l.backfill` today covers relays and asks
  only, and Stage B extends it. Four opens stuck on NFS or FUSE would otherwise park all four workers.
- Launch probes the deputy (spawn, one `ADDFD|SEND` round trip; `ADDFD|SEND` needs 5.14, `pidfd_getfd` 5.6).
  If the probe fails, the affected gate cells stay (D) and are recorded in `best_effort`, with a warning. They
  are never silently continued.

## Performance

**Measured.** Unprivileged tier 1, Linux 6.17, GOMAXPROCS=4, machine load 4–7, real seccomp listener and real
`ADDFD`, with a throwaway benchmark harness that was not committed. An earlier "+15–25 µs" is **retracted**:
its harness did not run `PrepareAskOpen`.

| Path | Per open/connect | Notes |
| --- | --- | --- |
| `CONTINUE` | 13–18 µs | today's ungated fast path under load |
| copy + walk + `CONTINUE` (today's gated open) | 42–71 µs | |
| production `PrepareAskOpen` + `CompleteAskOpen` + `ADDFD` | **270–680 µs**, typically ~500 | 10–40× |
| persistent-executor prototype (no creds or umask work) | 107–137 µs | ~2× today's gated path |
| relay connect vs `CONTINUE` (loopback) | +12–32 µs (52–77 → 71–102 µs) | Step 3's cost |

- **Causes in the production path.**
  - `runAskOpenAs` locks a goroutine to a fresh OS thread and exits it, so the runtime destroys the thread. This
    happens twice per open (155–176 µs for a no-op call).
  - Four `/proc` status reads per open at tier 1 (`ReadTaskCreds` ~22 µs, `taskUmask` 15–20 µs, `ThreadCreds`
    23–27 µs twice). At root tiers `RunAs` adds a thread and more reads.
  - 460 allocations and 57 KB per open, against 28 and 5 KB on the gated path.
  - The ceiling with 4 workers is about 8k opens/s.
- **Consequence.** That path, generalised, misses E17 (4–8 µs per notification;
  30k in 0.15–0.25 s) by 10–40× and exceeds R22's 200 µs soft ceiling on every open. It is not a candidate.
  *Amended 2026-10-06 (kill test 5, supervisor.md E17):* E17's 4–8 µs and 0.15–0.25 s for 30k were the design
  baseline's estimate, not a measurement, and E17 now gives the measured figures: 45–52 µs for the round trip of an
  fs open in the 6.17 guest on a quiet host (supervisor.md R15b), and 60–280 µs of run time for each
  notification an `fs.ask` entry keeps, end to end in kill test 5's 2-vCPU guests on a shared host. The multiple above
  was taken against the estimate. The conclusion does not rest on it: 270–680 µs exceeds R22's 200 µs soft ceiling on
  every open.
- **Stage B budget.** BenchmarkHeldOpen is committed next to `BenchmarkSeccompNotifyRoundTrip`. Ratios are
  taken against the gated path on the same run, so machine load cancels out. The prototype must meet all of:
  - held read-open of an existing regular file: p50 ≤ 2× today's gated copy+walk+`CONTINUE`;
  - p99 < 200 µs at tier 1 on an idle box, so R22 holds;
  - no OS-thread creation per open;
  - zero `/proc` reads per non-`O_CREAT` open at tier 1;
  - ≤ 64 allocations per open;
  - 30k held opens in ≤ 1 s wall across the default 4 workers. E17 is restated with this figure.

  Measured as well: a held write-open with `O_CREAT`, and a read gate (every read-open of the run is held). If
  the budget is missed, held completion of **allow** verdicts ships as an explicit contract opt-in, named by the
  follow-up. The default cells stay (D) and are disclosed. The root-tier path is measured in KVM.
- **Step 2.** Notifying the chmod family under a write gate adds one round trip per `fchmodat`/`fchmod`
  (~15–60 µs; `fchmod` also reads `/proc/<pid>/fd`). Step 2 measures a 10k-file `tar x` with and without a
  write gate and records the figure in gate.md.
  *Measured 2026-10-16 (Step 2's note below; gate.md R4):* GNU tar 1.35 extracting 10,000 files under tier 1 at
  `record: summary`, with and without `fs.write outside worktree: 90`. A plain `tar xf` makes no mode change, and
  the gate added a median 46 ms (paired, within noise). `tar xpf` of an archive whose modes carry a setuid bit makes
  10,000 `fchmod` and 101 `fchmodat2` calls, and the gate added a median 586 ms to it (1,193 → 1,805 ms; bare tar
  233 ms): about 51 µs per notified mode change once the write-open cost is taken out, inside the 15–60 µs above, at
  a machine load of 7–9. At load 15–20 the same figure was about 84 µs.
- **Step 3.** The relay is +12–32 µs per IP connect or send under a net gate, plus the D6 regime.

## Rejected options

1. **Keep the unconditional `deny_write` refusal with no opt-out and no ADR** (as is). Rejected: it
   gives no recorded way to run the commonest contract at the only unprivileged tier. Options (b) and (b+)
   keep its default and add the opt-out.
2. **Document the gate race and change nothing.** Rejected for net, where the relay is cheap and race-free.
   Accepted as the **interim** state for fs open gates: (D), disclosed, until Stage B meets its budget.
3. **Held-fd for `deny_write` write-opens**. Rejected: it buys no security while mutations stay on
   copied names at the same tier, and it puts the held cost on every write-open of the default git contract (D8).
4. **CONTINUE fall-through for non-regular objects, `O_TMPFILE` or lookup failures**. Rejected:
   the branch is chosen by attacker-controlled bytes. A probe measured directory, `/dev/null`,
   `/dev/urandom`, FIFO, `/dev/stdout` and `O_TMPFILE` all returning `EOPNOTSUPP`, and missing paths returning
   `ENOENT`/`ENOTDIR`. D4 decides each class.
5. **A supervisor executor thread restricted with the run's ruleset**.
   Rejected: no run cgroup, so the plane and fanotify skip it; tego's LSM label; a sibling Landlock domain. A
   scratch result (0 of 32 threads inherited the domain) stands, but it proves only the Landlock
   half.
6. **Supervisor-side inode-identity checks against the plane rows as the confinement mechanism.** Rejected as
   the primary mechanism: nearest-wins ancestry, Landlock, fanotify and the host LSM would all have to be
   reproduced in userspace. `(dev, ino)` verification is kept for the delivered descriptor (D3 step 6).
7. **Relay unix datagrams, or unix connects with no `net:` section, under a net gate.** Rejected:
   they would be performed with tego's credentials and cwd, outside the agent's abstract-socket scope.
8. **Relay `sendmmsg` batches.** Rejected (I3): the result would be fabricated.
9. **Evaluate the gate in the kernel plane.** Rejected (ADR 0007). The plane decides lists and inodes.
10. **Key the relay on the copied family**. Rejected (D6): the family word is itself mutable.
11. **A tier-scoped `errorf` for `deny_write` at compile.** Rejected as stated:
    `firstError`/`HasErrors` ignore `Diagnostic.Tier`. The workable form is the `setuid`-style `errorf` at a
    pinned, uncapped landlock tier (D8).
12. **Cache the umask per tgid**. Rejected: umask is per `fs_struct`, changes at runtime, and tgids
    are reused. A stale value creates a secret with mode 0644 after the agent set 077. It is read only for
    `O_CREAT` instead.
13. **A per-run `gap what=enforce why=deny-write-unraceable`**. Rejected: `what=enforce` counts
    plane refusals already made, and a static fact on every default run would drown real gaps in
    `internal/check/gaps`. run_start `best_effort` replaces it.
14. **Emulate gated non-open mutations in the deputy** (rename, link, unlink, symlink, mkdir, mknod, chmod,
    truncate on pinned parents). Rejected **now** for cost and semantic surface: rename flags, cross-directory
    `REFER`, and the `link` follow rules. It is not impossible, and it is the path to any strict gate mode later.
15. **Scope held routing to plane-less runs** (S9). Rejected for gates: the plane carries no gate rule, so C+/B
    need the held path too. It is right for `deny_write`, which is why `deny_write` gets no held path at all. On
    `choosePlane`'s listener fallback (rows changed or over capacity at C⊘), a filter composed for a plane keeps
    opens notified whenever a gate kind escalates (`gateRead`/`gateWrite`), so held routing does not depend on
    which way the plane choice went. `ErrPlaneRowsChanged` remains an error, as today.

## Implementation plan

Repo rules apply to every step:
- Write a failing regression test first and record its output; then fix.
- Docs change in the same commit, as dated amendments.
- `gofmt -l .` must be clean.
- `go vet` runs in the four tag sets, and `golangci-lint` runs on the changed packages.
- Root-tier behaviour is checked in a KVM guest (`test/vm/root-suites.sh`, `VM_BOOTS=both` where the plane
  matters).
- No change under `bpf/` or `internal/bpf/` is planned. If the deputy's runtime exec row needs a plane change,
  `scripts/check-bpf-objects.sh --fix` runs in that commit.

### Stage A: independent, cheap, testable unprivileged with the real seccomp harness

**Step 1: walk-failure completeness.**
- **Change.** `supervisor/fs.go` `settleFS`/`gateFS` passes `complete=false` when the end's walk failed with
  anything that is not `lookupFailure`/`errGone`, *or* with `errOtherView` on a **linked** object. A
  nameless-object `errOtherView` (pipe, socket, anon inode, unlinked file; `describeImage`'s `linked`/link
  prefix) stays complete. `gateOpen` also evaluates when `d.verdict` is observed/path-unreliable, instead of
  returning early.
- **Test.** TestGateFSWalkFailureRefusesUnreadable, with a fake `FSTarget` returning EMFILE, ENFILE, ENOMEM,
  EIO, EXDEV and linked-other-view. It asserts `gate.unreadable` and `fs-gate`. The nameless-object case and
  `ENOENT` still score as today.

**Step 2: chmod under a write gate.**
- **Change.** `landlock/filter.go` adds the Chmod arm whenever `rt.Gate.Has(gate.FSWrite)`; `filterOpts` gets
  `gateWrite`. The golden filter tests are updated.
- **Test.** TestWriteGateNotifiesChmod at `record: summary` and `off`.
- **Measure.** The `tar x` cost (§Performance).

**Step 3: the net gate relays on IP-domain sockets (D6).** The
fix lands first.
- **Change.** `net.go` `resolveSocket` reads `SO_DOMAIN` under `Gate.Has(gate.Net)`. A new `t.ipGated` feeds
  `refusesUndecidable` and clears `t.dec.continued` for IP-domain sockets after gating. `send.go`'s Fast-Open
  and datagram branches use `ipDomain`. A source-route check is added in front of `relay`. Compile warns about a
  net gate with no `net:` section.
- **Tests.**
  - `TestGateConnectPrecedesRelayAndNoNetRecordOffShortcut` pinned the bypass; it now asserts the relay. This
    corrects the test, it does not weaken it.
  - TOCTOU integration tests (real `BuildFilterMemfd`, real `Loop`, uid 1000): TestGateConnectRelayedRaceFree,
    TestGateFastOpenRelayedRaceFree and TestGateSendtoRelayedRaceFree. A sibling flips **the port and the
    family word** (`AF_UNIX`↔`AF_INET`) between a benign and a gated destination. They assert that 0 of N reach
    the gated listener. Controls: the same gate plus a `net:` section, and a direct gated connect (`EACCES`).
  - A family-mismatch unit test.
  - TestGateRelayRefusesSourceRoute.
  - Record the pre-fix counts.

**Step 4: read predicates on rename/link sources (S8).**
- **Change.** `gateFS` also evaluates `FSRead` predicates on the source end of `FSRename`/`FSLink` and keeps the
  stronger verdict.
- **Test.** TestGateReadMatchesScoresRenameAndLinkSource (deterministic; fails today).

**Step 5: disclosure (D7).**
- **Change.** `RunStartPayload.BestEffort` plus a record_minor bump and README text. Compile adds `unenforced`
  warnings per cell id. CAPABILITIES rows are appended (R23); `drift` and `status` show the field. Rule ids go
  into `tools/rulecheck`.
- **Tests.** `TestGoldenEvents`, the payload field-list test (payload_test.go:32), compile goldens, and
  TestRunStartBestEffortListsGateCells.

**Step 6: `deny_write` per D1 (after D1 is answered).** Inventory for (b)/(b+); under (a) the same files
change, with the default assertions moved under `assurance: kernel`:
- schema: `pkg/spec/agent` field, `agent.go`, `spec/agent/v0/agent.schema.json` and its agreement test;
- `compile_denywrite.go`: errorf/warn per D8 and the opt-out values;
- `print.go:147`: `kernel-plane-required` versus `best-effort(opt-out)`;
- `internal/cli/compile.go:725`;
- The refusal sites, which admit the opt-out: `enforce/select.go:122-134`, `landlock/landlock.go` `Prepare`,
  `cgroup/planerun.go:37-54`;
- `internal/policy/decide/evaluate.go` `evalDenyWrite` doc comment;
- The run_start `best_effort` id and the new capability row;
- tests that **keep** their default refusal and **gain** opt-out cases:
  `test/conformance/kernel_integration_test.go:240-258` (exit 125 and message on non-bpflsm axes),
  `cgroup/plane_e2e_integration_test.go:426`, `landlock/negativewrite_test.go`,
  `pkg/spec/agent/compile_denywrite_test.go:105` (it asserts the absence of `best-effort(supervisor`; it now
  asserts the absence by default and the presence under the opt-out), `internal/cli/compile_test.go:168`,
  `TestSelectProtectedWritesRequiresActualPlane`, `select_capacity_test`,
  `TestProtectedWritesRequirePlaneBeforeAnyRuleIsBuilt`, `TestProtectedWritesNeverFallBackToListener`;
- new tests: TestDenyWriteOptOutRunsAtLandlock (a real `git init` worktree at tier 1: exit 0, run_start
  `best_effort` lists the id, protected-writes row false), TestDenyWriteBestEffortKeepsEarlyRefusal (b+),
  TestCompileDenyWriteErrorsAtPinnedLandlock;
- KVM: C⊘ with the opt-out (listener-only run admits), C+ unchanged.

### Stage B: gated on the deputy prototype; it ships only if the D2 confinement and §Performance budget are met

**Step 7: prototype the deputy.**
- `launch/child.go` starts `__open-deputy` after `restrict_self` and cgroup placement, before the listener
  filter.
- The runtime exec grant is added (Landlock rule, plane exec row at B), with its effective-policy display.
- The deputy runs with `PR_SET_DUMPABLE 0`, its allowlist filter and the socketpair protocol.
- Launch probe and degrade (§Consequences, Availability).
- Commit BenchmarkHeldOpen with the budget assertions. If the budget is missed, stop and amend this ADR.

**Step 8: held completion for escalating gate kinds; ADR 0008 completions move to the deputy.**
- `pkg/policy/gate`: `MayEscalate(kind)` reuses `New`'s subset-sum with "> allow" in place of the ask range.
- `supervisor/gate.go` `gateOpen` and `fs.go` `recordOpen`: route every open of an escalating kind through D3
  and D4. `ask_open.go`'s executor is replaced by the deputy client, which removes `runAskOpenAs`'s per-call
  thread and the `RunAs` and status reads.
- R21 backfill and the ceiling extend to held opens.
- Ledger per D5, with `gate_facts: held_object` and a record minor bump.
- At tier 2 the kernel recorder and plane record skip the deputy's tgid (R7a).
- **Tests.**
  - TestGateFSOpenRaceIsHeldAndRaceFree: a sibling flips the name between a gated `*.env` and each of a
    benign regular file, a **directory**, **`/dev/null`** and a **missing path**. It asserts 0 bypasses and
    that the delivered fd is the scored inode. Record the pre-fix count.
  - A **differential suite**, kernel open versus held open with identical results and errnos, over `O_APPEND`,
    `O_EXCL`, `O_TRUNC`, `O_NOFOLLOW`, `O_DIRECTORY`, `O_PATH`, `O_TMPFILE`, dirfd-relative paths, a trailing
    slash, `ELOOP`, `ENAMETOOLONG`, `EFAULT`, parallel `O_CREAT` creators (no spurious `EEXIST`), and umask
    after a runtime `umask(077)`.
  - Landlock-equivalence tests: a held write-open refuses exactly what Landlock refuses, including after
    renames of write-entry ancestors. The delivered fd carries `TRUNCATE`/`IOCTL_DEV` restrictions.
  - ADR 0017 conformance cells with hard-link, bind-mount and overlay fixtures, asserting that a held open never
    exceeds the kernel path's answer.
- **KVM** (`VM_BOOTS=both`):
  - a held open at a root tier with a non-root agent (RunAs creds), then `tego status`/`stop`/`approve` as
    non-root (threadcreds.go:138-144 made the whole launcher non-dumpable under `RunAs`);
  - tier 2 one line per action (R7a);
  - The conformance cells on C⊘, C+ and B;
  - The root-tier BenchmarkHeldOpen.

### Docs (same commits as the behaviour; dated notes, never rewrites of accepted text)

- **ADRs.**
  - `docs/adr/0041-*.md` (this ADR) and its README index row.
  - `Amended by 0041` on 0007 and 0008.
  - Dated notes on 0016 and 0024 for the stale "supervisor decides `deny_write` as a tier-1/2 producer" lines
    (0016 lines 8 and 72), worded per D1.
- **docs/p0/gate.md.**
  - R1: the `errOtherView` split.
  - R3/R4: the D1 table, D4 classes, the name-not-inode residual and the D6 blast radius.
  - R4: "Allow score → ordinary operation path" becomes the (A)/(D) cells.
  - R5: `gate_facts: held_object`.
- **docs/p0/supervisor.md.** R7, R7a (deputy tgid), R9, R13b, R15, R15c, R15d, R16b; R21 (held-open backfill);
  R22 and E17 restated with the Stage B budget.
- **docs/p0/agent-contract.md.** R20 per D1 (and `assurance` only under (a)); R22a (completion matrix,
  `held_object`).
- **docs/p0/enforce-landlock.md.** R5a per D1, and the runtime exec grant (Stage B).
- **docs/p0/enforce-plane.md.** The deputy is an in-run opener; its exec row (Stage B).
- **spec/policy/SEMANTICS.md.** §2 (`deny_write`: the plane is the race-free closure; the default per D1) and §3
  (gate completion).
- **Record and capabilities.** `spec/backend/CAPABILITIES.md` appended rows; `spec/record/v1/README.md` and the
  record-ledger doc for `best_effort` and `held_object`.
- **CHANGELOG.**

## The D1 question

**D1 (scope and UX, not architecture).** At tiers landlock and cgroup-without-plane, the `deny_write` default
is one of:
- **(b)** refuse, with `fs.deny_write: []` to opt out;
- **(b+)** refuse, with `[]` or `fs.deny_write: best-effort` to opt out. **Recommended.**
- **(a)** best-effort by default, with a top-level `assurance: kernel` to opt in to strict.

Until D1 is answered, Stage A Steps 1–5 proceed and Step 6 waits. *Since answered:* D1 was decided (a) and Step 6 is
built; the 2026-10-05 note near the end says why.

## Implementation notes

*2026-10-05, Stage A:*
- **Step 1** built as specified: `walkIncomplete` in `settleFS`/`gateOpen`, `errLinkedElsewhere` for a
  linked object this process cannot see, and `gateOpen` gating a path-unreliable open
  (`TestGateFSWalkFailureRefusesUnreadable`: 18 of 24 cases continued before).
- **Step 3** built: `resolveSocket` reads `SO_DOMAIN` under a net gate,
  `ipGated` clears `continued` and skips the unix relay, the source-route refusal (`relay-source-routed`) guards
  every ipGated relay, and compile warns about a net gate with no `net:` section. Before, 131 of 600 raced connects
  and 135 of 600 Fast-Open sends reached the gated port; after, 0 (datagrams 0 before and after). One deviation:
  `refusesUndecidable` is not passed `ipGated`. Unparsed families and `AF_UNSPEC` already refuse as
  `gate.unreadable` through `gateNet` on every path, and routing them through `refusesUndecidable` would only rename
  that refusal `unmatched`, against D6's own "keep refusing as `gate.unreadable`".
- **Step 3, amended 2026-10-05 :** The source-route read was a snapshot a sibling's `setsockopt` could
  race. The filter's source-route arm (enforce-landlock R11b, `sourceRouteTest`) refuses those options under a net
  gate (`TestNetGateFilterRefusesSourceRouteOptions` failed on all five option cells on both architectures before;
  `TestFilterRefusesSourceRouteOptionsOnKernel` shows the kernel accepting both routes from an unprivileged task
  without the arm and refusing them with it).
- **Step 4** built for the source end, and the destination too under `RENAME_EXCHANGE`
  (`TestGateReadMatchesScoresRenameAndLinkSource`).
- **Step 5** built except the capability-matrix rows: `gate.MayEscalate`/`MayEscalateBy`,
  `RuleTable.BestEffortCells`, one compile warning per cell, `run_start.best_effort` at record minor 6, and the
  `status`, `events` and `drift` views. Appending the five R23 rows changes every run's capability line, `doctor`'s
  matrix and their goldens, and is left to its own change. `compile --test` columns do not show the cells yet.
- **D8, under every option:** the `deny_write` finding is a compile error at a pinned or machine-held tier landlock
  (`TestCompileDenyWriteErrorsAtPinnedLandlock`). The auto-contract warning was left as it was rather than
  narrowed `.only(landlock)`: it describes the listener-only cgroup refusal too.
- **Not built:** Step 2 (chmod under a write gate), Step 6 (waits on D1), Stage B.

*2026-10-05, Step 6 (D1 decided (a), the note below):*
- `fs.assurance: best-effort | kernel` (`agent.FSAssurance`, `RuleTable.FSAssurance`, `FilesystemAssurance`, the
  stricter of the compiled and the contract value) in the schema tree, `spec/agent/v0/agent.schema.json`, the merge
  (the stricter wins; `fsAssuranceOutvoted` warns) and contract_hash.
- Compile warns `unenforced` once per target, at its write entry (`warnDenyWrite`), naming the target, best effort
  and `deny_write/default`, its fix naming `fs.assurance: kernel`; none for a table held at tier bpflsm. Under
  `kernel` the D8 error above applies, per target, and elsewhere a warning (`TestCompileDenyWriteErrorsAtPinnedLandlock`
  now sets the key); by default it no longer applies (`TestCompileDenyWriteBestEffortByDefault`). A search cut by a
  limit says so in a warning of its own for the entry.
- `enforce.Select`, the Landlock `Prepare` (enforce-landlock R5a) and tier cgroup's `choosePlane` refuse only under
  `kernel` (`RuleTable.DenyWriteNeedsPlane`), naming `fs.assurance` and the fix; by default the listener fallback
  takes such a table again, also when a plane cannot hold it.
- run_start `best_effort` lists `deny_write/default` where no plane decides the run (`RuleTable.BestEffortCellsAt`,
  from the run's tier and `decision_plane`); `status` and `drift` say "decisions on copied syscall facts".
- The printed table and `compile --json` mark a target `best-effort(supervisor; landlock: parent writable)` /
  `best_effort` by default and `kernel-plane-required(...)` / `kernel_plane_required` under `kernel`.
- Tests: the refusal tests of Step 6's list keep their names and now set `fs.assurance: kernel`
  (`TestSelectProtectedWritesRequiresActualPlane`, `TestProtectedWritesRequirePlaneBeforeAnyRuleIsBuilt`,
  `TestProtectedWritesNeverFallBackToListener`, `TestCompileDenyWriteErrorsAtPinnedLandlock`, the select capacity
  tests); the default has its own (`TestSelectProtectedWritesBestEffortByDefault`,
  `TestProtectedWritesBestEffortByDefault`, `TestProtectedWritesFallBackToListenerByDefault`,
  `TestCompileDenyWriteBestEffortByDefault`, `TestBuiltInDenyWriteSet`); and `TestFSAssuranceKey`,
  `TestFSAssuranceMergeKeepsKernel`, `TestBestEffortCellsDenyWrite`, `TestCompileAndRunAgreeOnDenyWrite` (the
  commands, unprivileged), `TestIntegrationDenyWriteBestEffortAtLandlock` (a real tier-1 run),
  `TestPlaneRunEndToEnd`'s listener cell, and
  conformance: `denywrite` runs its cells on the landlock and listener axes again, and `denywrite-kernel` (the same
  under `fs.assurance: kernel`) is refused there with exit 125 and runs its cells on the plane axes.
- Not built: D7's `protected write targets` capability row, which goes with Step 5's other rows.

*2026-10-16, Step 2:*
- The filter change was built on 2026-10-05 (`filterOpts.gateWrite`, enforce-landlock R11): the chmod family
  is notified under an `fs.write` gate at every record level, with
  `TestWriteGateNotifiesTheChmodFamilyUnderEveryRecordLevel` (both architectures, through the BPF VM) and
  `TestWriteGateNotifiesChmodOnRealKernel`. This note finishes the step.
- `TestWriteGateNotifiesChmod` (supervisor, integration) is the step's named test, end to end on the real kernel, the
  real filter and the real Loop under `record: summary` and `off`: `fchmodat` and `fchmod` outside the worktree are
  refused with the gate's authority and one refused line each, with the mode left as it was, and a mode change inside
  the worktree is continued. With the filter built as before (`gateWrite` false) both outside calls succeed and the
  modes become 0777 and 0755.
- The golden filter dumps gain the write-gate form on both architectures (`filter_x86_64_gate_write.txt`,
  `filter_arm64_gate_write.txt`, `TestWriteGateFilterGolden`): the plain filter plus the chmod family's notify arm.
- The `tar x` measurement is in §Performance and gate.md R4.
- Departure: the plan named the test `TestWriteGateNotifiesChmod` at `record: summary` and `off` for the filter; the
  filter half already had its own tests, so the name went to the end-to-end test, which shows the step's effect on what
  the agent can do.

*2026-10-16, Step 5's capability rows (D7):*
- D7's five rows are appended after `exec.command_argv` (R23; no earlier index moves), in D7's order, with these wire
  names: `gate.fs_open_completion` ("gate fs open completion"), `gate.fs_mutation_completion` ("gate fs mutation"),
  `gate.exec_completion` ("gate exec"), `gate.net_completion` ("gate net completion") and
  `fs.protected_write_targets` ("protected write targets"). The step 5 note's "five R23 rows" and step 6's "D7's
  `protected write targets` row" are the same five: D7 lists four gate rows and the protected-write-targets row.
- Cells. The gate's fs open, fs mutation and exec rows are best effort at every tier (Stage B is not built, no kernel
  layer evaluates a gate predicate, and the kernel copies argv again). The gate's net row is present at every tier:
  the relay of D6 on IP-domain sockets, its cell naming the unix residuals. Protected write targets are best effort at
  tier landlock (the supervisor refuses write-opens and mutations of a target on copied pathnames and does not refuse
  a chmod there, supervisor R15c), conditional at tier cgroup (a plane mode, not the fanotify listener) and present at
  tier bpflsm. `fs.deny_write` is untouched.
- A run answers two of them itself (`runtime.capabilityLine`): `gate.net_completion` only while a started supervisor
  answers its notifications, as `ask`; `fs.protected_write_targets` exactly where a plane mode decides the run, the
  reading `BestEffortCellsAt` takes from `decision_plane`, so the row and `deny_write/default` cannot disagree. The
  tier-2 handle sets the latter from its plane mode too, and `doctor` turns tier cgroup's conditional cell on from its
  plane probe, with a note either way. An adoption claims no `gate.net_completion` (no supervisor); a boundary
  adoption claims `fs.protected_write_targets` from its own plane mode, beside the four plane rows it already lists.
- Goldens: no committed golden carries a whole capability line (`status` renders it from the ledger), so the change
  shows in `TestMatrixGolden` (CAPABILITIES.md cell for cell), the row-count tests, and the run, handle and doctor
  tests that name the rows (`TestCompletionRowsOfADR0041`, `TestCapabilityLineCompletionRows`, the plane and tier-3
  handle tests, `TestCapabilitiesNarrowPerRun`, `TestMachineMatrixTurnsOffWhatThisKernelCannotDo`,
  `TestIntegrationRunStartSaysWhatTheRunHad`). The step 5 note expected regenerated goldens; there were none to
  regenerate.
- No record minor: the capability line's keys follow CAPABILITIES.md, every appended row has been additive within v1,
  and a reader keeps a key it does not know.
- Conformance (added with the `compile --test` columns): `RunCapabilityCrossCheck` holds every axis's real run to
  the row, true exactly where the run's `decision_plane` is `lsm` or `fmod_ret`. In the KVM guest (6.17, both boots)
  the `denywrite` and `denywrite-kernel` fixtures report no problem on any axis (landlock, the fanotify listener,
  `fmod_ret`, `lsm`, bpflsm).

*2026-10-16, Step 5's `compile --test` columns (D7):*
- Each column of a row names the best-effort cells its answer rests on (`agent.RuleTable.BestEffortCellsFor`):
  `best_effort: [<id>, ...]` on the `--json` cell (additive, `v: 1`; ADR 0019 gains an amended-in-part line) and
  ` [best effort: <id>[ at <tier>, ...]; ...]` on the text line (limits-check-doctor-cli R28).
- The reading, decided here: the ids are the column's tier's `BestEffortCellsAt` cells, narrowed to the row. A gate cell
  holds when the row is its action (read-open, write-open, delete or mkdir, a rename's source and its mutation, exec,
  a unix connect) and the floor did not refuse first, and it holds for a gate refusal as for an allow, because a
  sibling can race a continued benign spelling to the refused one, so the refusal is no more a boundary than the
  allow. `exec.rules/argv` holds for an exec row a command rule allowed or asked, beside the `argv_assurance: copied`
  ADR 0048 already shows; a command rule's refusal is (R), not this cell. `deny_write/default` holds for a modification refused under a built-in target's rule.
- Tier cgroup's column is read with no decision plane: compile probes no machine (R33), so it discloses
  `deny_write/default` there as the compile warning does; the bpflsm column's plane decides the targets and lists none.
- Rejected: a column marker only for allows (it would print a bare PASS beside a refusal any sibling can bypass), and a
  per-table footer listing the contract's cells (the compile warnings already do that; a row needs to say which of them
  its own answer depends on).
- Tests: `TestCompileTestShowsBestEffortCells` (text and `--json`, every tier; it did not build before the field
  existed) and `TestBestEffortCellsForARow`.

*2026-10-16, fixes of Step 2 and Step 5:*
- An older bug beside this work: a read gate never scored an open that reads with a write bit
  (`O_RDWR`; `O_RDONLY` with `O_CREAT` or `O_TRUNC`). `gateOpen` and `gateFS` took it for a write, and under a gate
  with no `fs.write` predicate continued it unscored, so `exec 3<>a.env` read a secret the read-only open was refused,
  every time, with no race: a name predicate must catch every way to read the file, Step 4's reason. Such an open is
  now scored with the read predicates as well, the stronger verdict kept, in `gateOpen`, `gateFS`, both held-open
  paths and R5's fail-closed answer (`decide.OpenReads`; gate.md R1, amended). `compile --test` keeps one direction
  per row (an `fs.write` row is the conformance actor's `O_WRONLY` open), so a run's answer for an open that does both
  is the stronger of its two rows; scoring an `fs.write` row with the read predicates was rejected, since it would
  refuse an `O_WRONLY` write the run allows. Departure from the first idea, which asked for `EvaluateGateRow` to
  score it too: no row carries an access mode. Fixed here rather than in a separate package,
  because it is a deterministic fail-open of a gate cell this work discloses and its fix is local to the scoring.
  Tests: `TestGateReadScoresAnOpenThatReads`, `TestGateReadGuardsAFailedHandlerForAnOpenThatReads`,
  `TestGateReadScoresAHeldOpenThatReads`, and `TestGateReadRefusesAReadWriteOpen` on a real kernel and filter (the
  `O_RDWR` descriptor read `SECRET=1` before).
- `EvaluateGateRow` scored an `fs.rename` row with the write predicates only, and with none answered the floor's
  `allow` for the rename of a secret out of its name that a run refuses `fs-gate` (Step 4). Its source is now scored
  with the read predicates too, as `gateFS` scores it, so the column answers the run's refusal and tags it
  `gate.fs.read/move` (`TestBestEffortCellsForARow`, `TestCompileTestShowsBestEffortCells`).
- A boundary adoption under a plane mode said `fs.protected_write_targets: false` while its `best_effort` left out
  `deny_write/default`. The plane's rows hold the built-in targets for every task in the cgroup (`heldAcross`
  compiles them with `decide.CompilePlane`), so the adoption now claims the row from the same plane mode, and the row
  and the cell agree for an adoption as for `tego run`; a target held open across the adoption is the open-files gap,
  as for `fs.deny_write` (`TestAdoptBoundaryNamesThePlaneAndItsRows`). Rejected: listing `deny_write/default` in the
  adoption's `best_effort`, which would disclose as copied a decision the plane makes by inode.
- The column tagged `exec.rules/argv` on an exec a command rule refused. ADR 0048 and SEMANTICS class that
  refusal (R) (a refused exec never runs) and the cell an allow's (D), as the matrix cell (`a refusal is exact`) and
  the compile warning say; the race to a refused argv goes through an allow of another argv, which the cell already
  names wherever the table has command rules. The cell is now tagged for a command rule's allow or ask only (the
  refused-subcommand row of `TestCompileTestShowsBestEffortCells`). The gate cells keep tagging refusals: a gate cell
  is (D) whole (D1), early refusals included.

*2026-10-16, more fixes of Step 2 and Step 5:*
- A write gate's refusal of a mode change was bypassed by setting a POSIX ACL. `setfacl -m u::rwx,g::r-x,o::r-x
  ../outside/p.txt`, or `setxattr(…, "system.posix_acl_access", …)`, made a 0600 file outside the worktree 0755 while
  every chmod form of the same change was refused, with no score and no ledger line: the filter notified the xattr
  family under no option. The product already counts an ACL write as a mode change (the plane's `inode_set_acl` lines
  are `op: chmod`). Under `filterOpts.gateWrite` the filter now notifies the xattr family (`setxattr`, `lsetxattr`,
  `fsetxattr`, `removexattr`, `lremovexattr`, `fremovexattr`, and 6.13's `setxattrat` and `removexattrat`) and, for
  the same reason, the chown family (`chown`, `lchown`, `fchown`, `fchownat`): a chown hands the group bits to another
  group, the same class of change. The supervisor handles each as a chmod (`recordAttr`): `op: xattr` or `op: chown`,
  scored by `gateFS` as a write of the file it lands on, continued and recorded `allow` when the gate allows it, and
  refused beneath a `deny_write` target where a plane mode decides the run (the plane's `path_chown` and xattr hooks
  refuse it there), and R5's fail-closed answer refuses it under a write gate. Design choices: every attribute name is
  scored, never only `system.posix_acl_*`, and the name is never read, because the supervisor's copy of the name is
  one a sibling thread can rewrite before the kernel reads it; the line's op names the syscall's family (`xattr` for an
  ACL set), not the plane's hook. Rejected: scoring only the ACL names (a check a peer defeats, and `user.*` writes
  outside the worktree stayed unscored); notifying the families under `record: full` too (a record-level change this
  finding does not need; E35 keeps saying `record: full` records chmod only); notifying timestamps (`utimensat`,
  `utimes`, `futimesat`, `utime`), since they change no permission and no content and GNU tar sets one per extracted
  file (201 `utimensat` for 200 files under `strace -c`), so a write gate would make every extraction pay a round trip
  per file for a change no gate predicate is about; that residual is a D1 row and is disclosed in the `gate fs
  mutation` cell. Cost: GNU tar 1.35's `xf` and `xpf` make no xattr or chown call unprivileged (`strace -c`, 200
  files: 0), so Step 2's measurement stands; `tar --xattrs --acls -xpf` makes one `setxattr` per file, which a write
  gate now notifies at the per-round-trip cost measured for chmod (about 51–84 µs; derived, not measured end to end).
  Tests: `TestWriteGateNotifiesTheAttributeFamilies` (filter, both architectures, every record level),
  `TestWriteGateScoresAnAttributeChange`, `TestAttributeChangeIsNotScoredWithoutAWriteGate`,
  `TestAttributeChangeUnderThePlaneRefusesADenyWriteTarget`, `TestGateFilesystemFaultScope`'s new rows, and
  `TestWriteGateNotifiesXattrAndChown` end to end at `summary` and `off` (with the arm removed the outside file
  becomes 0755 and no line is written, a reproduction). The golden write-gate filters are regenerated.
- The reading of an open that reads also caught a mknod, which is recorded as an `O_CREAT|O_EXCL` open whose
  access mode reads `O_RDONLY`, so a read gate refused `mkfifo fifo.env` and `mknod reg.env` that read nothing (fail
  closed, but a refusal whose line names a read rule for an action that read nothing). `recordOpen` marks a mknod's
  decision (`fsDecided.mknod`) and `gateFS` scores it with the write predicates only; flags alone cannot tell it from
  an `O_RDONLY|O_CREAT|O_EXCL` open, which reads and is still refused (`TestGateReadLeavesAMknodToTheWritePredicates`).
- R5's fail-closed answer (`fsGuarded`) continued a rename or link under a read gate
  alone, although `gateFS` scores its source with the read predicates (Step 4), so a handler that panicked or returned
  without answering let the rename of a secret out of its name through. An earlier fix extended `fsGuarded` to opens that read
  only. It now returns true for `rename`, `renameat`, `renameat2`, `link` and `linkat` whenever the gate scores
  `fs.read` (`TestGateReadGuardsAFailedHandlerForAnOpenThatReads`, `TestGateFilesystemFaultScope`'s read-gate rename
  and link rows). Fixed here, not left to Step 4, because it is the half that fix left of the same reasoning.

*2026-10-16, Stage B Step 7 (built; the budget's ratio term missed, so Stage B ships as an opt-in, below):*
- **The deputy.** `internal/runtime/deputy` (wire protocol, allowlist filter, `Main`, client), its walk
  `supervisor.DeputyPin`, `tego __open-deputy`, and the child stage's `spawnDeputy` (`launch/deputy.go`, a reviewed
  process-start site) after `landlock_restrict_self` and before the listener filter, given `ChildSpec.Deputy`. It is
  cloned with `CLONE_PARENT`: its parent is the launcher, a subreaper, never the agent the stage becomes, so no
  `wait(2)` of the agent meets it. At a root tier the exec gives it the agent's uid, gid and groups and no
  capability. It sets `PR_SET_DUMPABLE 0`, arms `PR_SET_PDEATHSIG` against the launcher, sets no_new_privs, installs its
  filter with TSYNC, says hello on the control socket (the launcher reads its pid from `SCM_CREDENTIALS`), reports
  readiness to the stage, then serves one request socket per concurrent caller. Nothing in a run starts it yet: the
  runtime sets neither `ChildSpec.Deputy` nor `supervisor.Options.Deputy` until Step 8's opt-in.
- **Departures.** (1) No plane exec row: the run's plane row goes in at Arm, after the stage reports (ADR 0021 (2)),
  and the deputy's exec completes before the report, so it is no event of the plane, as the stage's own exec of tego
  is not; the Landlock exec grant is Step 8's, needed only where the run restricts `EXECUTE`. (2) The filter is D2's
  list plus what the Go runtime needs: clone only with `CLONE_THREAD`, clone3 answered `ENOSYS` (libc falls back to
  clone), kill and tgkill only to itself, read and write only of the runtime poller's eventfd (write to standard
  error), fcntl status and close-on-exec only, `prctl(PR_SET_VMA)` answered `EINVAL`, and `openat2`; anything else is
  `SIGSYS` (`TestDeputyFilterKillsForbiddenSyscalls`: execve, fork, socket, ptrace, ioctl, a signal to another process,
  a write to a file, an fcntl lock). *Amended 2026-11-02:* a read of any other descriptor is answered `EPERM`, not
  `SIGSYS`, so the deputy still reads no file and lives on. A cgo build's glibc reads one by itself: the first time one
  of the deputy's threads needs a ninth malloc arena, `arena_get2` counts the CPUs from
  `/sys/devices/system/cpu/online`, then `/proc/stat`, then `sched_getaffinity` (allowed), and concurrent requests
  start threads. Killed there, the deputy died with requests in flight, and every held open after it was refused
  `held-unavailable`: the race job (cgo) failed `TestDeputyPinsAndOpens`, `TestHeldReadsSixtyFourThreads` and
  `TestGateFSOpenRaceIsHeldAndRaceFree` on Ubuntu 24.04's glibc 2.39, and so does a plain cgo build of the supervisor
  suite there (17 of 20 runs of the 64-thread test on two CPUs; none after). Ubuntu's 2.35 and 2.43 kill it the same
  way; the shipped `CGO_ENABLED=0` binary has no libc and was never affected (`TestDeputyFilterRefusesAFileReadAndLives`,
  `TestFilterRefusesAReadItDoesNotKillFor`). (3) The pin is one lookup where it can be: the deputy shares the task's root,
  mounts and credentials, so `openat2` from the task's cwd or dirfd with `RESOLVE_NO_MAGICLINKS` is the task's own
  lookup save procfs's `self`, `thread-self` and magic links, which fall to the walk (`pinInRun`: 3 µs against 14.5 µs
  for the walk). The supervisor sends the task's tgid; the deputy reads no /proc file. (4) A read-only open of a regular
  file or a directory is pinned and opened in one exchange (`opPinOpen`), sent before the copied name is checked so
  the two overlap: an open with no effect but atime, delivered only once every check of the pin passes, dropped
  unseen otherwise. Every other open is made after the checks. (5) An `O_PATH` open cannot be held: ADDFD's `fget`
  ignores `O_PATH` files (`EBADF`). It stays on the copied name, a refused name refused and any other continued, a
  disclosed cell of its own (`gate.fs.read/o_path`): such a descriptor reads nothing, and every access to contents
  through one is another open, held.
- **Probe and degrade.** A deputy that does not start fails nothing: the stage reports it on the deputy's own control
  socket (`deputy.ReportFailure`), which the launcher reads in place of the hello (`deputy.Hello`: `ErrNotStarted`,
  or `ErrUnavailable` for a missing or forged hello), and the run continues with the cells disclosed.
- **Tests.** `TestStageStartsTheDeputyInTheRunsDomain` (attested hello, `CLONE_PARENT`, no capability, not dumpable,
  filter and no_new_privs on; the stage's Landlock domain refuses the deputy's create outside the write directory and
  allows it inside), `TestStageReportsADeputyThatCannotStart`, the deputy package's `TestDeputyPinsAndOpens` (6,400
  concurrent exchanges under its filter) and `TestDeputyIsNotDumpable`, and on a real listener and loop
  `TestGateFSOpenRaceIsHeldAndRaceFree` (a sibling flips a read-open's name between `*.env` and a file, a directory,
  /dev/null and a missing name: 390 of 3,200 reached the secret through the best-effort cell, none held, benign opens
  delivered) and `TestHeldOpenDifferential` (35 cases, kernel open against held open, errno for errno: `O_APPEND`,
  `O_EXCL` new, existing and on a symlink, `O_TRUNC`, `O_NOFOLLOW`, `O_DIRECTORY`, `O_PATH`, `O_TMPFILE`, dirfd-relative,
  trailing slashes, a dangling create, `ELOOP`, `ENOENT`, `ENOTDIR`, `ENAMETOOLONG` of a component and of the path,
  `EFAULT`, eight parallel `O_CREAT` creators, a runtime `umask(077)`, /dev/null, /dev/zero, a FIFO, a pipe through
  /proc/self/fd).
- **BenchmarkHeldOpen** (`supervisor/held_integration_test.go`; gated and held alternated in five rounds, the median of
  the per-round ratios), on this shared 16-CPU 6.17 box, never idle (load 0.4 to 0.9 per CPU while it ran), nine runs:
  held p50 60 to 195 µs against gated 29 to 85 µs, median ratios 1.83, 1.92, 1.93, 2.01, 2.01, 2.03, 2.13, 2.29 and
  2.35: **TARGET-MISS, 2.01× at the median (budget 2×)**. The other terms: p99 85 to 379 µs, under 200 µs in seven runs
  of nine, on a machine that was never idle (the idle-machine term is not measurable here); no OS thread made per open (at most
  3 over 37,000); no task /proc read per non-`O_CREAT` open (one per thread, its tgid); 22 to 27 allocations per open
  (budget 64); 30,000 held opens across four workers in 0.93 to 3.7 s (budget 1 s on an idle box; met in two runs of
  nine, idle never). Most of the difference is two cross-process wakeups per held open, the deputy's and the worker's,
  which on a loaded host cost about what the gated path's whole round trip does; the rest is the deputy's lookup and
  reopen (about 6 µs) and the pinned path's identity (about 4 µs). A spin before the blocking receive made it worse
  (2.35×) and was dropped.
- **The root-tier path, in KVM** (§Performance: "the root-tier path is measured in KVM"). `BenchmarkHeldOpenRootTier`
  runs the loop as root over a tier cgroup table, the target and its deputy as the invoking user, so a held read-open is
  pinned, checked and only then opened, two exchanges where tier landlock's overlaps the open with the checks. In the
  6.17 guest (4 vCPUs, lsm-bpf boot, load 0.34 per CPU and no CPU time stolen by the host over the run): held p50 117 µs
  against the gated path's 28 µs, **TARGET-MISS 4.14×**; p99 157 µs (met); 30,000 held opens across four workers in
  1.83 s (**TARGET-MISS**, budget 1 s); 23 allocations per open, no task /proc read per open, no thread per open. The
  tier landlock path in the same guest: held p50 85 µs against 30 µs, **2.83×**; p99 123 µs (met); 30,000 in 1.25 s
  (missed); 22 allocations per open. On the default-lsm boot (the plane in fmod_ret mode, 0.1% and 0.7% stolen): the
  root tiers' path 131 µs against 37 µs, 3.51×, p99 188 µs, 30,000 in 1.90 s; tier landlock's 97 µs against 40 µs,
  2.73×, p99 185 µs, 30,000 in 1.36 s. An earlier guest run on a host other jobs' guests shared gave 2.08× and 3.10×,
  p99 287 and 316 µs. The benchmark's idle-machine terms (p99, the 30,000) are asserted only where the one-minute load is below
  0.5 per CPU and under 2% of the CPU time was stolen by a host over the run: a guest's own load average says nothing of
  its host's, and the first guest run asserted them on a host that was not idle. The decision below stands; both paths
  miss the ratio.
- **Decision, by §Performance's own rule.** Held completion does not become the default: it ships with Step 8 as the
  explicit contract opt-in this note names, `gate.completion: held`. Without it every Stage B cell stays (D) and
  disclosed, as before Stage B.

*2026-10-16, Stage B Step 8 (built as the opt-in `gate.completion: held`):*
- **The opt-in.** `gate.completion: copied | held` (default `copied`) in the schema tree, `agent.schema.json` and the
  gate compiler (`gate.Policy.HeldCompletion`); `RuleTable.NeedsOpenDeputy` (held, and an fs kind that can score past
  `allow`); `held` that holds nothing warns `redundant-rule` (`TestGateCompletionKey`). The runtime starts the deputy
  for such a table (`ChildSpec.Deputy`), reads its hello after the stage reports, hands it to the supervisor
  (`Options.Deputy`), ends it once it is the run cgroup's last process and reaps it; one that did not start warns, and
  the run's `best_effort` keeps the open cells (`BestEffortCellsRun`, the degrade). The Landlock runtime exec grant
  (`kindDeputy`, enforce-landlock) holds tego's binary where the domain handles `EXECUTE` (`TestDeputyExecGrant`).
- **The cells.** Under `held` with the deputy up, `gate.fs.read/open` and `gate.fs.write/open` are (A): the open is
  checked on its copied name, pinned by the deputy, decided on the pinned object (D3, D4), opened by the deputy in the
  run and delivered by `ADDFD|SEND`. `gate.fs.read/o_path` is a new (D) cell (Step 7's departure (5)); the move and
  mutation cells are unchanged. The default `copied` changes nothing.
- **Ledger.** `gate_facts: held_object` at record minor 10 (`record.MinorHeldObject`), on the ordinary fs line with
  the pinned object's path; failures and undelivered opens carry E35's fields. An errno the deputy's open meets (D4's
  "errno that describes the task's state") is the task's answer and the line's `syscall_ret`, and the verdict follows
  the recorder's rule for a refusal the kernel returned (ADR 0016 (1), (3), `decide.ChainFS`): an `EACCES`, `EPERM` or
  `EXDEV` the tier's model explains (`decide.Evaluate` at the run's tier) is that mechanism's refusal, under the model's
  rule and reason; any other errno keeps the floor's verdict. The first cut wrote every `EACCES` and `EPERM` refused with
  a contract reason under the floor's allowing rule, which named a refusal no contract rule made where the file's own
  permission bits answered. The kernel recorder drops every record of the deputy (`SetSkipPID`), the plane's refusal of
  one of its opens included, so a held open is one line at C+ and B (the conformance cell
  `fs-held/write-open-deny-read-nested-in-write` at tier bpflsm, where the floor this loop shares with the copied path
  allows the write-open and the plane refuses it, was two lines while the recorder kept the plane's record and this loop
  wrote its allow); at C⊘ a fanotify listener's refusal of what the floor allowed is the listener's own line beside this
  loop's, a residual named in supervisor R7a. The deputy opens only after the checks at a root tier (no read-only open
  ahead of them).
- **Departure: the floor of an allowed held open is the copied path's.** D3 step 3 lists `deny_read`
  (`decide.NearestIn(...).DenyRead`) and `AskDenyWriteTarget` among the checks "exactly as `gateOpen`/`askOpen` apply
  them today", and those two apply them to the ask range only. An open the gate allows takes `decideFS`'s floor on the
  copied path, the contract's verdict for the tier (`decide.AdvisoryFS`, which leaves a `deny_read` nested in a write
  entry unenforced at tier landlock, ADR 0016) and R15c's `deny_write` targets; the held path applies that same floor on
  the pinned object (`heldFloors`), and the ask range adds the stricter two before a person is asked (`heldAskFloors`).
  Rejected: the stricter floor on every held open, which refused at tier landlock the reads and write-opens beneath a
  nested `deny_read` that the tier documents as unenforced and the copied completion allows (the conformance suite's
  `fs-held` cells `read-deny-read-nested-in-write` and `write-open-deny-read-nested-in-write` failed so): the key would
  change which opens a tier allows, not only how they complete, and the kernel's own decision on the deputy's open stands
  beneath the floor either way.
- **Departure: ADR 0008 completions.** D2 moved every human-approved open to the deputy. A gate ask (the ask range on
  an open the floor allows) is pinned, approved and opened by the deputy under `held`. An `fs.ask` or `fs.ask_read`
  approval is not moved: those scopes carry no kernel right of the run's by design (SEMANTICS §3.1, §6; enforce-landlock
  holds them for identity only), so an open in the run's own context would be refused by its Landlock domain and, at a
  root tier, its plane, and making it succeed would give the run's kernel context the right an ask withholds. They keep
  the supervisor-thread completion, the residual §Consequences named, and so do alternates (ADR 0057): a person's
  alternate for a held gate ask is offered and completed as on a hold of the supervisor's own pin, the person's file
  reopened as the task's credentials and umask and delivered in the target's place, with `gate_facts: held_object` on
  its line (`TestHeldGateAskTakesAnAlternate`). Rejected: a second Landlock layer for the deputy carrying the ask scopes
  plus a plane exemption keyed on its pid, which takes the deputy out of the plane's decisions for every open and keeps
  the supervisor's userspace check the only floor of those scopes anyway.
- **Tests.** `TestIntegrationHeldCompletionAtLandlock` (the real binary at tier landlock, unprivileged: an exec:
  section, so the grant is needed; a benign read held and delivered, the secret refused by the gate on the pinned object,
  `held_object` at minor 10, `best_effort` without the open cell), with Step 7's. Landlock equivalence:
  `TestDeputyDescriptorCarriesTheDomainsFileRights` (a descriptor the deputy opened under a domain that grants no
  `TRUNCATE` cannot be truncated, its `O_TRUNC` open is refused, and an ioctl on its `/dev/zero` is refused for want of
  `IOCTL_DEV`; the same opens outside any domain carry neither restriction) and
  `TestIntegrationHeldOpenNeverExceedsLandlock` (the parent of a write entry moves away during the run and a new
  directory takes the entry's name; the create there by name, which the floor allows and a person approves, is refused
  by the run's Landlock rule when the deputy makes it; the copied completion made it on a supervisor thread outside the
  domain and succeeded, the pre-fix outcome). ADR 0017 cells: the conformance suite runs the `fs`, `link` and `denywrite`
  fixtures again as `fs-held`, `link-held` and `denywrite-held`, under a gate that holds every open and scores none of
  their actions, so each cell's kernel answer, ledger line, effects and invariants are held to the same expectations
  with every open completed by the deputy (symlinked spellings, a hard link out of a protected tree, the `deny_write`
  targets), and the run's `best_effort` must not list the open cells (`Model.HeldOpens`). Root tiers:
  `TestIntegrationHeldCompletionAtRootTier` at tier cgroup and tier bpflsm (agent dropped to the user; a held read, a
  gate refusal on the pinned object, a gate ask approved with `tego approve`, `status` and `stop`, one line per
  action). Departure from Step 8's KVM list: its `status`/`stop`/`approve` "as non-root" cannot be run against a root
  launcher's live run, whose directory is root's until its Close hands it to the user (record-ledger's hand-over rule;
  `TestIntegrationRootSweepEndsARootLauncherTheUserCannot`), so the user's commands are refused by design, not by the
  launcher's dumpable flag; the case runs them as root, the run's owner while it runs. The flag the item was about is no
  longer touched by an approved gate ask under `held`: the deputy opens it, and no supervisor thread takes the agent's
  credentials for it (`sys.RunAs`). *(Corrected the same day: the note said no supervisor thread takes
  them under `held` at all.)* An alternate a person names for a held gate ask is still checked and reopened on a
  supervisor thread as the task's credentials and umask (`runAskOpenAs`, `sys.RunAs`), and so are every `fs.ask` and
  `fs.ask_read` completion (the departure above); at a root tier each of those still makes the whole launcher
  undumpable for the rest of its life (`commit_creds` resets the flag to `fs.suid_dumpable`, threadcreds.go), as before
  Stage B. `BenchmarkHeldOpenRootTier` is the root tiers' path of
  `BenchmarkHeldOpen` (the loop as root over a tier cgroup table, the target and its deputy as the user, the open after
  the checks). Verified as root in the 6.17 KVM guest on both boots (lsm-bpf and default-lsm, one guest each running
  the suites root-suites.sh runs them with): the supervisor's held tests (their target and deputy as the invoking user,
  as a run drops its agent; as root the deputy, which takes no capability, could not walk a root target's /proc), the
  launch, observe and runtime held tests in both builds (tier bpflsm on the lsm-bpf boot only, its skip listed in
  root-skips.txt for the other), and `TestConformanceKernel` on every axis the boot offers with the held fixtures.
- **Not built.** ADR 0017 cells over bind mounts and overlayfs: the suite has no such fixture yet (`Deferred`,
  `fs/bind-mount-and-overlayfs`, ADR 0017 space (5)), and the held variants join it when it lands; the D7 capability
  rows (Step 5's).

*2026-10-16, Stage B fixes:*
- **The deputy is named by its identity, and its pid is held.** The kernel recorder dropped every record of
  the deputy's pid for the whole run (`SetSkipPID`). The deputy runs with the agent's uid, so the agent can end it, and
  the run's reaper then reaped its zombie, a child of the launcher in the run cgroup, which freed the pid: a later
  process of the run given it had every record dropped, the plane's refusals included. Now the recorder takes the
  deputy's pid and its start time, read from /proc right after its hello while it is the launcher's unreaped child
  (`SetSkipProcess`; a record must carry the deputy's start, `proc.SameProcess`), and the reaper leaves the deputy's
  zombie for the run's `closeDeputy` (`launch.Child.KeepUnreaped`), so no later process of the run is given the pid at
  all. Rejected: clearing the skip when the deputy exits, which lets the deputy's own records still in the ring after
  its exit through as second lines; treating the deputy's death as a run failure, which hands the agent a way to end
  its own run with no rule broken (held opens fail closed without it, `held-unavailable`). A launcher in a time
  namespace with a boottime offset reads a start that never matches: the deputy's records are then written beside the
  supervisor's lines, a second line and never a lost one. Tests: observe's
  `TestRecorderKeepsARecordOfTheDeputysPidFromAnotherProcess` and `TestSkipProcessDrops` (the pid-only skip failed
  both), launch's `TestReapOrphansKeepsTheDeputy`, and `TestIntegrationKilledDeputyKeepsItsPid` (the real binary at
  tier landlock; the deputy killed from outside, its zombie still unreaped a second later and reaped at the run's end;
  with the reaper's exclusion removed it was reaped at once).
- **A held open made and not delivered says so.** A descriptor that fails D3 step 6's identity check is never
  delivered. For a read-only open, which had no effect but atime, that stays a refusal, `held-unavailable`. Any other
  was made by the deputy (a create whose new leaf a sibling renamed before the check had made its file), so its line
  is D5's partial completion, E35's `operation_completed: true`, `fd_delivered: false` with the task's `EACCES` as
  `syscall_ret`, and it counts `orphaned`; it was a refusal line for an open whose side effect had happened
  (`TestHeldCreateWhoseLeafMovesIsRecordedAsMade`, `TestHeldOpenWhoseIdentityFails`, both failing before).
- **D4's re-pin is built.** The deputy's create beneath the pinned parent adds `O_NOFOLLOW`, so a symlink that
  appeared at the leaf after the pin failed the agent's `O_CREAT` open `ELOOP`, where the kernel's own open follows
  it; the code made one open and let the errno stand, against D4's row and its own comment. Now an `EEXIST` or `ELOOP`
  of such a create is pinned, checked and scored once more (`mayRepin`) and the second answer stands, unless the agent
  asked for `O_EXCL` (or `O_NOFOLLOW`, for `ELOOP`), whose errno is the kernel's answer, or a person approved the
  absent leaf: an approved create is made `O_EXCL` and a file that appeared during the wait is never put in its place
  (ADR 0008), so its errno stands too. `TestHeldCreateRepinsALeafThatAppeared` compares the delivered descriptor with
  the kernel's own open of the name once the link is there (into the worktree: the link's target, delivered; out of
  the write entry: refused by the floor on the new pin; with the agent's `O_NOFOLLOW`: `ELOOP`, no re-pin); every case
  answered `ELOOP` before.
- **D3 step 1 for the holds of a person's scope.** Under `held` an open an `fs.ask` scope or an `fs.ask_read`
  entry holds is decided by `askOpen`/`askReadOpen` before `heldOpen`, and they scored the gate on the name their own
  pin reached alone. Now, when a deputy serves the run, the gate's score of the copied name where this loop's walk of
  it landed, as `heldOpen` takes it, is taken first, and its refusal is final (`heldCopiedRefusal`): a sibling that
  re-points a link between the walk and the pin cannot move a write-open or a read from a name the gate refuses to
  one it scores lower and reach a person. The object a hold delivers was always the one it pinned, so this was a
  divergence from D3, not a bypass; and the copied completion's holds never took the copied score either (`gateOpen`
  scores only an open the floor allows), so they are unchanged. `TestHeldAskScopeRefusesOnTheCopiedName` (both scopes;
  both asked a person before).
- **D3's checks on the pinned object have tests that fail without them.** Removing the gate's score of the pinned
  object, or the `deny_write` floor on where the pin landed, failed no committed test: the race test flips only the
  copied pathname, and the conformance suite's held fixtures score none of their actions. The differential suite now
  opens a benign name that is a symlink to the gated `*.env` file (refused by the gate on the pinned object, the
  secret never delivered; with the score removed it was delivered) and appends through a symlink to the harness's
  `deny_write` target `.git/config` (refused by the floor on the pinned object, as the copied path's walk refuses it,
  the file unchanged; with the floor removed the append went through).
- **Held opens answer as the kernel does for `O_CREAT` on what exists, and for flags it refuses.** The deputy's
  reopen of a pinned existing object dropped `O_CREAT` and `O_EXCL`, so `open(dir, O_RDONLY|O_CREAT)` delivered the
  directory where the kernel answers `EISDIR`, and `O_CREAT|O_EXCL` of `.` opened it where the kernel answers `EEXIST`.
  It now keeps both (`openPinned`; only `O_NOFOLLOW`, which the walk honoured, is dropped), and the kernel answers the
  reopen as it answers the task. Three answers of the same family came with it. An `O_CREAT` open of a name followed by
  `/` is `EISDIR` whatever the name holds, since the kernel refuses the slash before it looks the name up; the walk had
  answered the name's own `ENOENT` or `ENOTDIR`, or pinned a directory (`trailingSlashCreate`, in the deputy's walk:
  the parent's walk errno, then the parent's search `EACCES`, then `EISDIR`). Flags the kernel refuses before it reads
  the pathname (`O_CREAT|O_DIRECTORY` from Linux 6.4, `O_TMPFILE` with `O_CREAT` or without write access) are its
  `EINVAL` even where the walk would fail, asked of the running kernel with an empty pathname (`openFlagsInvalid`, one
  syscall, for flags carrying `O_CREAT` or `__O_TMPFILE` only). And the differential suite's trailing-slash cases had
  tested nothing: `filepath.Join` cleaned the slash away, so they opened `d`, `f` and `nope`; with the slash kept,
  `trailing_slash_creat` was a divergence too (the kernel's `EISDIR`, held `ENOENT`). `TestHeldOpenDifferential` now
  holds 49 shapes (the cases above, `O_CREAT` and `O_CREAT|O_EXCL` on a directory and on `.`, `O_CREAT|O_DIRECTORY` on a
  directory, a new name and beneath a missing one, `O_TMPFILE` read-only and with `O_CREAT`, and the trailing slash
  on a file, a directory, a missing name with and without `O_EXCL` and beneath a missing directory); nine failed
  before. Residual, by code reading: an `O_CREAT` open (no `O_EXCL`) of an existing regular file in a sticky directory
  is reopened through `/proc/self/fd`, whose directory is not sticky, so `fs.protected_regular` does not refuse it as
  it refuses the task's own open of a file another user owns there; a held open can then succeed where the kernel's
  own would fail `EACCES`. Closing it needs the pin of an existing file to name its parent and leaf, so the deputy
  opens it by name as a create does; not built yet.
- **A pin reached by a name that is gone is unreadable, not nameless.** The supervisor took every pin with no
  link left as nameless (D4's row for a pipe, an anonymous inode or an unlinked file behind `/proc/self/fd/N`), which
  skips the floors and the gate's score on the pinned object. A file the deputy pinned through a benign name (a
  symlink to a gated file) whose last name a sibling removed before the supervisor read the pin was so decided on the
  benign copied name alone and delivered. The deputy's pin reply now says whether the walk reached the object through a
  descriptor (`deputy.Pinned.ByDescriptor`, a flag bit of the reply: `AT_EMPTY_PATH`, a procfs magic link as the
  walk's last step, or a relative walk's start named by `.` alone), and a pin reached by a name with no link left is
  refused `gate.unreadable` (`pinnedPath`'s `errNameRemoved`); one reached through a descriptor stays nameless, as D4
  says. A file system that reports no link for a named file is refused the same way, failing closed.
  `TestHeldPinWhoseNameIsRemovedIsUnreadable` (the symlinked secret, unlinked just after the pin, was delivered
  before; an unlinked file behind `/proc/self/fd` is still delivered), `TestDeputyPinSaysHowItReached`, and the
  protocol's round trip and the deputy's integration test for the bit.
- **Not built: D2's LSM label check.** D2 has the deputy compare the task's `/proc/<tid>/attr/current` with its
  own label where a task-labelling LSM is active and refuse a mismatch `held-label-differs`. No code reads a label on
  the held path, and the Step 7 and Step 8 notes neither built it nor listed it. A held open is the deputy's, made under
  the deputy's own label (the tego binary's, unconfined on a stock host), so a process of the run that an AppArmor
  profile or a SELinux domain confines more tightly (an agent binary with a profile of its own, or a tool it execs into
  one: AppArmor lets an unconfined task enter a profile under no_new_privs) is not held to that confinement for its
  held opens. This contradicts the enforce-plane amendment's "a held open is never more permissive than the agent's
  own" for such a process; it is a residual, disclosed here, in gate.md R4's held note and in supervisor R7a, and a run
  that starts its deputy on a host whose active LSMs (`/sys/kernel/security/lsm`) include AppArmor, SELinux or Smack
  warns once that the check is not built (`heldLabelWarning`, `TestHeldLabelWarning`; on a host whose list cannot be
  read it warns too). Why not built yet: a sound check needs the task's label at the moment of each open. A
  read of `attr/current` per held open breaks §Performance's "no task /proc read per non-`O_CREAT` open" on every
  stock Ubuntu host, where AppArmor is always active; and no sound cheaper key was found. A cache invalidated at the
  task's execve notification races a sibling thread's held open between that notification and the exec's own
  transition (the sibling refills the entry with the old label, which the leader inherits with the thread group's
  pid once `de_thread` runs), and a label change written through `/proc/self/attr` is a `write(2)` on a descriptor
  opened earlier, which the supervisor never sees. Rejected meanwhile: refusing held completion on any host with a
  task-labelling LSM, which refuses it on every Ubuntu host for a confinement most runs never enter.
- **Verified** as root in the 6.17 KVM guest on both boots (lsm-bpf and default-lsm), the held, deputy, reaper and
  recorder tests of the observe, launch, runtime and supervisor packages in both builds where they have two
  (`TestIntegrationHeldCompletionAtRootTier` at tier cgroup and, on the lsm-bpf boot, tier bpflsm;
  `TestIntegrationKilledDeputyKeepsItsPid` as root, the agent dropped to the user; the 49-shape differential and the race
  test with a non-root target and deputy), and `TestConformanceKernel` on every axis each boot offers with the held
  fixtures. On the default-lsm boot a first run, on a loaded host, failed two conformance runs that do not involve these
  changes to a held open's decision: a
  `denywrite-held` run at tier landlock whose deputy missed its start (the run then lists the open cells best effort,
  the degrade) and two `execrules` exec lines at `cgroup@fmod_ret` written `observed` (a quick process's relative exec
  name the recorder could not resolve after it exited, the load race §Performance and ADR 0017's exec cells name). The
  same suite rerun on that boot with the host otherwise quiet passed on every axis, and `tego doctor` with it.
  `BenchmarkHeldOpen` before and after these changes, on a host under load (2.1 per CPU): 23.4 and 23.5 allocations per
  open, held p50 197 µs both, no task /proc read per open; `BenchmarkDeputyPinOpen` 224 B and 2 allocations per op
  both. Both runs miss the ratio as before (2.17× and 2.37× at the median of five rounds, the per-round spread 2.15 to
  3.07): no budget changes.

*2026-10-17, Stage B:*
- **Merged.** Stage B was built on an earlier tree; the tree since gained Step 2's and Step 5's work
  and the approval fixes (an `O_RDWR` open scored by the read predicates too, `scoreOpen`; an
  alternate put to the gate and its line carrying the alternate's own gate decision). The merge
  keeps both. A held gate ask's alternate check still called `alternateRefusal` alone, so the person's file was put to
  the protected paths and not to the gate at answer time; it now takes the hold's own `alternateCheck`
  (`TestHeldGateAskTakesAnAlternate`'s "alternate the gate refuses", failing before: the check took a `*.pem` file that
  a 90-point rule refuses).
- **A read-write open is held and scored by the read predicates too.** The held path chose the open's gate
  kind with `isRead`, so an `O_RDWR` open was a write: under a read gate alone it was not held at all (`MayEscalate` of
  the write kind is false) and was decided on its copied name and continued, and under a read and a write gate it was
  held and scored on the pinned object by the write predicates alone, so a sibling that made the deputy's lookup reach a
  `*.env` file had its bytes delivered. The tree's `scoreOpen` already scored such an open on its copied
  name by both kinds; the held path now does the same: an open is held when either kind it is scored with can escalate
  (`openMayEscalate`: the read kind for an open that reads, `O_RDWR` and `O_RDONLY` with `O_CREAT` or `O_TRUNC`
  included), and the pinned object is scored by `scoreOpen`. `TestHeldReadWriteOpenIsScoredByTheReadGate` (a read
  gate alone, and a read and a write gate; before, no pin in the first and `TOKEN=1` delivered in the second).
- **The deputy confines itself on one thread.** The earlier KVM run's `TestIntegrationHeldCompletionAtRootTier`
  at tier bpflsm passed once and failed once with "the open deputy did not start (... no child processes)". The cause:
  a privileged stage starts the deputy before it sets no_new_privs on itself (the R4 swap: no_new_privs follows the
  credential drop), so the deputy's threads start without it, and no_new_privs is a thread's. `deputy.Main` set it on
  the thread it ran on and then installed its filter with TSYNC from whichever thread the Go scheduler had moved its
  goroutine to; on another thread the install was refused `EACCES` for want of no_new_privs, the deputy exited before
  its readiness message, and the run degraded to the copied cells, at random and only at a root tier (the unprivileged
  order sets no_new_privs before the exec, and the deputy inherits it). `deputy.Main` now locks its goroutine to its
  thread for the deputy's life, so no_new_privs and the TSYNC install are one thread's, and TSYNC carries both to every
  thread. `TestDeputyConfinesOnOneThread` starts the deputy from a process without no_new_privs, as a privileged stage
  is, and moves its goroutine off the thread between the two steps (a test seam, `confineStep`): five runs of five
  failed before with `seccomp(SET_MODE_FILTER, TSYNC): permission denied`; it passes, every deputy thread with
  no_new_privs and the filter. A start failure now names its cause: the deputy sends its fatal line on the readiness
  socket in place of the readiness byte, the stage puts it in its report (`deputy.ReportFailure`'s reason), and the
  run's warning says it; an end of stream with no line is a deputy killed or crashed before it could say
  (`TestAwaitReadyNamesWhyTheDeputyDidNotStart`; the launch test of a reported failure checks the reason). The deputy
  package joins the KVM suites (test/vm/suites.sh), so its tests run as root too.
- **The run's held warnings carry codes of their own.** Every warning the runtime printed through `Deps.Warn`
  was tagged `[swap-uncapped]`, the code of the one warning the hook was first made for, so the degrade ("the open
  deputy did not start") and the label residual were filed as swap warnings by a consumer keyed on the code. The hook
  now takes the code: `held-unavailable` for the degrade, `unenforced` for the label residual, `swap-uncapped` for the
  memory cap (`TestHeldWarningsCarryTheirOwnCodes`, `TestMemoryCapIntoSwapIsALimitsGap`'s code check).
- **No process of a held run is in a Landlock domain the deputy does not share.** D2 requires the deputy to
  have "the same Landlock domain" as the task. The deputy is started once, in the domain the child stage made, and a
  process of the run may make a domain of its own beneath it (`landlock_restrict_self` needs only no_new_privs, which
  every agent has): its held opens were then the deputy's, in the outer domain, and exceeded its own. A test
  run: `setpriv --landlock-access fs:read-file` with read rules on `/usr`, `/lib` and `/etc` read a worktree file;
  refused under `copied`, delivered under `held`. Decided: a held run's filter answers the three Landlock syscalls
  `ENOSYS` (enforce-landlock R10's held arm), as on a kernel without Landlock, so every process of the run is in exactly
  the deputy's domain and D2's requirement holds by construction. Rejected: (a) tracking the processes that restricted
  themselves and refusing or copying their held opens: at tier landlock the supervisor sees no fork, so a child of such
  a process, or one reparented to the launcher after its parent died, cannot be told from the run's other processes,
  and falling back to the copied completion for them would hand any agent a way to switch held completion off at will
  (restrict itself with a permissive ruleset, then race); (b) a deputy per nested domain, built from the task's ruleset
  descriptor: the ruleset can gain rules between the task's `landlock_restrict_self` and the copy's, so the copy's domain
  is not the task's, and the chains, the children and the descriptors of each make it a second sandbox to get right;
  (c) refusing only `landlock_restrict_self`, with `EPERM`: a library that probed the ABI and built a ruleset then fails
  where it would otherwise read the kernel as one without Landlock, and `EPERM` names a missing no_new_privs the
  process has; (d) disclosing the gap and changing nothing, which leaves a confused deputy the agent triggers itself. The
  cost, disclosed in compile's printed table: an agent that sandboxes its tools with Landlock, and a tego run inside
  the run, find Landlock unavailable under `held`. `TestHeldCompletionRefusesNestedLandlockDomains` (the arm on both
  architectures through the BPF VM, and Prepare setting it for a held table only) and the end-to-end run below.
- **A file whose name was removed is unreadable to a read gate (amends D4's "nameless object" row and Step 1).**
  D4 delivers a nameless object behind `/proc/self/fd/N` (a pipe, a socket, an anonymous inode, an unlinked file), and
  Step 1 takes a walk that reached one as complete facts, since no name can match it. For an unlinked regular file that
  was wrong: it had a name, possibly one a read gate refuses, and the gate scores neither a write-only open nor an
  unlink. So `open(secret.env, O_WRONLY)`, `unlink(secret.env)`, `open("/proc/self/fd/N", O_RDONLY)` read the secret
  with no race under both completions (a test run, at tier landlock on the host and at tiers cgroup and bpflsm
  in KVM: `allow unmatched`, `held_object`, path `/proc/self/fd/3`). The first fix for a gone name had kept this delivery on
  purpose. Now a regular file with no link on a filesystem with names (`unlinkedFile`: not the kernel's internal shmem
  mount, where memfds, System V segments and shared anonymous mappings lie, which never had a name) is
  `errUnlinkedFile`, an `errOtherView` every verdict still reads as nameless, and an open that reads it has no complete
  facts for the gate (`gateFactsIncomplete`): the read gate refuses it `gate.unreadable`, on the pin under `held`
  (`pinHeld`) and on the walk under `copied`. An advisory floor refusal no longer stops the gate when its facts are
  incomplete: under `copied` the `O_RDWR` reopen's spelling was refused by the write floor, a verdict this loop does not
  enforce at tier landlock, so the gate was skipped and the open continued, which Landlock allows (the unlinked file
  still lies beneath its write entry). Rejected: (a) scoring an unlink's removed name with the read predicates, as Step
  4 scores a rename's source: a read gate would refuse deleting a `*.env` file, and the unlink is a (D) mutation cell
  whose copied name a sibling can race, so the read would ride on a race again; (b) tracking which nameless files were
  made nameless by the run (`O_TMPFILE`), which an inode number's reuse can confuse. The cost: under a read gate an
  `O_TMPFILE` file, or a file the agent unlinked, cannot be reopened for reading through `/proc/self/fd` (its own
  descriptor reads it). `TestHeldPinWhoseNameIsRemovedIsUnreadable` ("an unlinked file by descriptor": `TOKEN=1` was
  delivered; "a memfd by descriptor" is delivered) and `TestGateReadRefusesAReopenOfAnUnlinkedFile` (the copied path:
  the read and the read-write reopens were continued; the write-only reopen and a memfd still are).
- **The deputy's walk follows a symlink only where the kernel would (D5's differential).** The pin is
  one `openat2` where it can be, a kernel lookup with the task's credentials, mounts and root; where that fails, or
  lands on procfs, the supervisor's walk takes over, and the walk read every symlink and walked its target in
  userspace. Two refusals of the kernel's `pick_link` were then lost: `fs.protected_symlinks` (`may_follow_link`, a
  trailing link in a sticky world-writable directory owned by neither the follower nor the directory's owner: EACCES)
  and a `nosymfollow` mount (ELOOP for any link on it). Both make `openat2` fail, so exactly those opens fell to the walk,
  which pinned the link's target and delivered it where the task's own open fails. The deputy's
  walk now applies both (`followFacts.mayFollow`, in `execWalk` when the walk is the deputy's): the follower's fsuid
  and the sysctl are read once, before the deputy's filter, which allows no read and no getuid (`DeputyPinner`, which
  `tego __open-deputy` passes to `deputy.Main`). The supervisor's own walks are unchanged: they place a name for a
  verdict, and a link the kernel will not follow fails the continued syscall. Owners are compared raw; on an idmapped
  mount the kernel compares mapped ones (a residual). `TestDeputyWalkFollowsLinksAsTheKernelDoes` (a link in `/tmp`
  followed by another uid: EACCES; by its owner, with the sysctl off, or mid-path: followed; it failed with the check
  removed) and `TestFollowFactsMayFollow`; as root, `TestHeldOpenDifferentialAcrossMounts` holds the two refusals and
  ADR 0017's bind-mount and overlay spaces and a hard link to the kernel's answers, case by case.
- **`fs.protected_regular` and `fs.protected_fifos` on a held `O_CREAT` open of an existing file (the residual
  of the `O_CREAT` note above, built).** The deputy reopens a pinned existing object through `/proc/self/fd`, whose directory is no sticky
  one, so the kernel's `may_create_in_sticky` never refused it: an `O_CREAT` open (no `O_EXCL`) of another user's file
  or FIFO in a sticky world-writable directory succeeded held where the task's own open fails `EACCES`. It granted no
  access the agent's own open without `O_CREAT` does not get (the sysctl protects an opener from a planted file, it is
  no confinement), but it was a divergence from the kernel's answer. This loop now makes the check on the directory the
  pinned path names (`heldStickyCreate`, `stickyCreate`: the task's fsuid and the sysctl read only when that directory
  is sticky) and answers the kernel's `EACCES` (`TestStickyCreate`; as root the differential's
  `protected_regular_creat` and `protected_fifo_creat`, with the same opens without `O_CREAT` and one of the agent's own
  file still opened).
- **A claimed gap, refuted.** D2 compares a later credential change at a root tier per object class, and no held code reads the
  task's credentials. None can happen in a held run: a gate needs `setuid` disabled (gate.md, `gate requires an
  enforcing tier with io_uring and setuid disabled`), so every task of the run has no_new_privs and no capability, and
  its credentials stay the ones the deputy was exec'd with (setresuid to its own ids changes nothing; setgroups needs a
  capability). `TestGateCompletionKey` now asserts that `setuid: true` with a held gate does not load.
- **Residuals kept, disclosed.** D2's LSM label check (the run warns `[unenforced]` on a host with AppArmor, SELinux
  or Smack active). Owners compared raw in the deputy walk's `protected_symlinks` check and in `stickyCreate`, where an
  idmapped mount compares mapped ones. A non-dumpable agent process's relative held open is `EACCES`, since the deputy
  cannot read its `/proc/<tid>/cwd` (D4's documented fail-closed divergence). At tier landlock a read-only open is made
  before the copied name is checked (it changes nothing but atime), so it can reach a FUSE or NFS server or a third
  party's fanotify listener before tego refuses the name. An `fs.ask` or `fs.ask_read` approval and every alternate
  still complete on a supervisor thread outside the run's domain (Step 8's departure, ADR 0008's residual). Under a
  read gate an `O_TMPFILE` file, or a file the agent unlinked, cannot be reopened for reading through `/proc/self/fd`
  (its cost); under `held` an agent finds Landlock unavailable for a sandbox of its own (its cost).
- **D7's `gate fs open completion` row and `compile --test` under `held`.** Step 5's capability rows were built on the
  tree while Stage B was on its branch, so the merged row still read "held completion is ADR 0041 Stage B,
  not built", and a held run's capability line said `gate.fs_open_completion: false` beside a `best_effort` without the
  open cells. The cell is now `conditional` at every tier (completed by the run's open deputy under `gate.completion:
  held`, best effort otherwise), and a run records it true exactly when its contract needs the deputy and the deputy
  serves a started supervisor (`runstart.go`; the degrade records false), as the net row is true only while the
  supervisor answers. The conformance suite's capability cross-check holds the row to `Model.HeldOpens`.
  `compile --test`'s columns read a held table as compile's own warnings do (the deputy taken to serve), so a read
  row the gate scores rests on no open cell; it named `gate.fs.read/open`, which compile did not warn of
  (`TestIntegrationHeldCompletionAtLandlock`'s capability check and `TestBestEffortCellsForARow`'s held rows, both
  failing before; `TestCompletionRowsOfADR0041`; `TestCapabilityCrossCheck`'s held cases).
- **Step 8's "Not built" list, revisited.** Step 5's capability rows were built on the tree
  and now carry Stage B (the bullet above). ADR 0017's bind-mount and overlay spaces are held to the
  kernel's answers by `TestHeldOpenDifferentialAcrossMounts` as root (a read, an append and a create through a bind
  mount; a read, an append and a truncation of a lower file, a create, a directory and a symlink through an overlay),
  which is Step 8's "a held open never exceeds the kernel path's answer" for those spaces; the conformance suite's own
  bind-mount and overlay fixtures, and their held variants, still wait on ADR 0017 space (5) (the generated conformance spaces).
- **End to end.** `TestIntegrationHeldCompletionClosesTheReviewedRoutes` runs the three routes through the
  real binary at tier landlock, unprivileged, under `fs.read matches "*.env"`: a read-write open of the secret, a read
  of a second secret through its descriptor after its name was removed, and `setpriv --landlock-access fs:read-file`
  reading a worktree file its own domain does not grant. Under `held` none reads what it reaches: the first two are
  refused by the gate (`gate.unreadable` for the reopen), and setpriv's `landlock_create_ruleset` fails `Function not
  implemented`. Under `copied` the two reads are refused too (the reopen by this fix), and the tool's own domain
  refuses its read.

*2026-10-17, Stage B, correctness fixes:*
- **The differential suite grows a generated matrix.** `TestHeldOpenDifferential` opens 393 shapes, once by the
  kernel for the task and once held: the 49 written cases; 22 more over directory descriptors and procfs starts (a
  file's descriptor, a symlink's `O_PATH` descriptor, an absolute name beneath a directory's, an empty name, `.`, `../f`
  and a create beneath one, a descriptor that is not open and a negative one; `/proc/self/cwd`,
  `/proc/thread-self/cwd`, `/proc/self/root`, `/proc/self/fd/N` and `/dev/fd/N` as a path's middle, a doubled slash
  and a `.` mid-path; the task's own `maps`, `environ`, `status` and `mem`); and a matrix of 23 pathname shapes (a
  file, a directory, a symlink to each, a dangling symlink, a loop, a FIFO of each case's own, a missing name and one
  beneath it and beneath a file, trailing slashes on each kind, `.` and `..`, a `.` mid-path, a read-only file, a file
  of mode 0 and a directory of mode 0) by 14 flag sets (each access mode, `O_NOFOLLOW`, `O_DIRECTORY` and both, the
  create forms with and without `O_EXCL` and `O_NOFOLLOW`, `O_RDWR|O_TRUNC`, `O_APPEND|O_NOFOLLOW`, `O_CREAT|O_TRUNC`,
  `O_TMPFILE` with and without `O_NOFOLLOW`), each with `O_NONBLOCK`, made in the same order on both sides so a create
  or a truncation an earlier shape made is the same for both. A table of kernel answers checks the fixture took effect
  (`heldMatrixKernel`). Thirteen shapes answered otherwise than the kernel, three causes:
  - **A final symlink that an open needing a directory does not follow is `ENOTDIR`.** The kernel checks
    `LOOKUP_DIRECTORY` before `may_open` refuses a symlink `ELOOP` (`do_open`), so `open(link, O_DIRECTORY|O_NOFOLLOW)`
    and `O_TMPFILE|O_NOFOLLOW` on a symlink are `ENOTDIR`, whatever the link points at; the deputy's walk answered
    `ELOOP` (eight matrix shapes). The pin now carries the open's need of a directory (`deputy.PinQuery.Directory`, a
    walk bit of the protocol, set for `O_DIRECTORY`, which `O_TMPFILE` carries), and the walk answers `ENOTDIR` there
    (`TestPinQueryWalkBitsReachTheWalk` holds every pin flag to the walk the deputy runs).
  - **An empty name is `ENOENT`, and a relative name beneath a descriptor the task does not hold `EBADF`**, both
    answered before the copied name is scored, after D4's `EFAULT` and `ENAMETOOLONG`: `getname` refuses the first and
    `path_init` the second whatever the name says, and neither leaves the gate a fact, so the copied name's score
    refused both `gate.unreadable` (`EACCES`), where D4 gives a lookup failure its own errno (four shapes:
    `empty_name`, `dirfd_empty`, `dirfd_not_open`, `dirfd_negative`). The reader records a directory descriptor the live
    task does not hold (`reader.noDirfd`: a negative one other than `AT_FDCWD`, or one `/proc/<pid>/fd` does not list);
    a sibling that opens that number after this loop read the list leaves the answer a valid order of the two calls,
    and nothing is opened. The copied completion keeps Step 1's `gate.unreadable` for both.
  - **The task's own `/proc/<pid>/mem` is `EACCES` held under Yama**, a fail-closed divergence beside D4's non-dumpable
    one (D4's `/proc/<pid>/…` row, amended here): procfs asks `PTRACE_MODE_ATTACH` of the opener when `mem` is opened,
    Yama at `kernel.yama.ptrace_scope` 1 or more (Ubuntu's default) refuses it to a process that is no ancestor of the
    task, which the deputy never is, and a thread group is never asked about itself. `maps`, `environ` and `status`,
    which ask `PTRACE_MODE_READ`, answer as the kernel does. The suite holds the held answer to `EACCES` where the
    sysctl is on (`heldFailClosed`). Rejected: `PR_SET_PTRACER` naming the deputy from the child stage, which reaches
    the agent's first process alone (Yama's exception is not inherited) and lets the deputy attach to it.
- **An open that needs a directory looks up a directory.** The pin's lookup now asks for one where the open does
  (`O_DIRECTORY`, which `O_TMPFILE` carries): `pinInRun`'s `openat2` takes `O_DIRECTORY`, and the deputy's walk ends in
  `ENOTDIR` on anything else, as the kernel's `LOOKUP_DIRECTORY` does before the open is made. A symlink in the worktree
  to a gated `*.env` file, opened `O_DIRECTORY`, was pinned, scored and refused `fs-gate` on the secret (`EACCES`, a
  refusal line), where the task's own open fails `ENOTDIR` and opens nothing (`symlink_gated_directory`, failing
  before); a gated name opened so is still refused on its copied name first (D3 step 1, as under `copied`;
  `directory_on_gated_file`). `TestHeldOpenDifferential` holds 395 shapes.
- **Residual, by code reading: an idle automount point.** The deputy's pin is `O_PATH`, and the kernel mounts an idle
  direct or systemd automount point a lookup ends on only for an open, a create, a directory lookup or a path's middle
  (`follow_automount`), never for a bare `O_PATH` one: a held open of the automount point itself without
  `O_DIRECTORY` (`open("/mnt/auto", O_RDONLY)`) opens the autofs directory, empty, where the task's own open mounts it
  and opens its root, and the walk (taken for procfs spellings, magic links and links the kernel refuses to follow)
  crosses such a point mid-path without mounting it and answers `ENOENT` beneath it, as supervisor.md R16b says of the
  exec walk. An `opendir` passes `O_DIRECTORY`, which the pin's lookup now takes (the bullet above), so it mounts the
  point as the task's own open would, by the kernel's rule; no test exercises it, since no guest of the suites has an
  automount daemon. Nothing beneath the contract is reached either way.
- **This loop's copy of a held open's descriptor is closed before the open's line.** It was closed when `openHeld`
  returned, after the line, which can wait on the ledger's queue (supervisor R23's backpressure); meanwhile the copy was
  a second reference to the open file description the agent held, so a FIFO the agent opened kept a reader or a writer
  after the agent closed it (a writer's `O_NONBLOCK` open succeeded where the kernel answers `ENXIO`; a reader of a
  FIFO the agent wrote waited for an end of file the copy held back), and an `flock` the agent released by its close
  stayed held. The matrix's FIFO shapes met it as a reader that was not the agent's. Now the copy is closed as soon as
  `ADDFD|SEND` returns, and that of a descriptor failing the identity check before the check's line is written
  (`TestHeldOpenClosesItsCopyBeforeItsLine`, failing before: a writer's open while the line was written found the
  loop's copy reading). Residual: the deputy's own copy is closed once its reply is sent, and this loop's once the
  delivery returns, so for the few microseconds after the agent's open returns the description has those references
  too; the matrix gives each FIFO shape a FIFO of its own for that reason.
- **A pin the task left is no deputy failure.** A pin whose reply was late (a lookup stalled on a mount) polls the
  notification (supervisor R21), and one the task left is abandoned. A read-only open's pin then fell to
  `heldUnavailable`: a warning that the deputy could not complete it and an anomaly counted, for a deputy that had
  failed nothing. It now answers nothing, writes no line and counts nothing, as for any notification its task left
  (`TestHeldPinTheTaskLeftIsNoAnomaly`, failing before with one anomaly for the read).
- **The check of a gone name has a test of its own.** Its one test was a read under a read gate, which a later fix
  refuses as an unlinked regular file too, so the test passed with `errNameRemoved` removed. The new case is a
  write-open under a write gate through a benign name in the worktree that is a symlink to a file outside it, unlinked
  just after the pin: with the check removed the deputy opened it for the benign copied name; with it the open is
  refused `gate.unreadable` and the deputy opens nothing (`TestHeldPinWhoseNameIsRemovedIsUnreadable`, "by name, a
  write"). Each earlier fix was re-run against a mutation that removes it (the pinned object's score, the
  read predicates on a read-write open and on its hold, the copied-name refusal of a person's scope, the re-pin, the
  unlinked-file refusal on both completions): each removal fails its test.
- **Verified** as root in the 6.17 KVM guest on both boots, with these fixes: the held, deputy, reaper,
  recorder and walk tests of the observe, launch, deputy, runtime, supervisor and landlock packages in both builds where
  they have two, `TestIntegrationHeldCompletionAtRootTier` at tier cgroup on both boots and tier bpflsm on the lsm-bpf
  boot in both builds, `TestHeldOpenDifferential` (395 shapes, the agent a non-root user) and
  `TestHeldOpenDifferentialAcrossMounts`, and `TestConformanceKernel` on every axis each boot offers; then the
  supervisor, deputy and conformance suites again on the final tip. `BenchmarkHeldOpen` before and after these fixes
  on the host, alternated (load 14 to 16 on 16 CPUs): ratios 1.74 to 2.10 before and 1.95 to 2.05 after, 22.3 to 22.7
  allocations per open before and 22.2 to 22.5 after, no task /proc read per open either way: no change. In the
  guest, on a host other agents' guests loaded (load 12 to 16), with under 2% of the guest's CPU time stolen on the
  default-lsm boot: tier landlock's path 2.58 to 2.87× (held p50 151 to 168 µs against 58 to 60 µs), p99 219 to
  244 µs, 30,000 held opens in 1.86 to 2.28 s; the root tiers' path 3.37 to 3.71×, p99 292 to 313 µs, 30,000 in 2.52
  to 2.74 s: TARGET-MISS on the ratio, the p99 and the 30,000, the gated path itself 50% slower than in the quiet
  guest of the Step 7 note, so the quiet figures there stand as the reference; 22.7 to 24.3 allocations per open, no
  /proc read and no thread per open. The lsm-bpf boot's guest had 24 to 41% of its CPU time stolen and its figures
  (3.66 to 5.40×) measure the host. No budget changes; held completion stays the opt-in.

*2026-10-17, Stage B, more fixes:*
- **A held open cannot reach the open deputy's own `/proc` tree (amends D4's `/proc/<pid>/…` row).** The
  deputy runs the walk and the reopen itself, and a process always passes `ptrace_may_access` against itself, so a
  held open of `/proc/<deputy-pid>/{mem,environ,auxv,maps,fd/N,cwd,root,exe,task/*/…}` was completed by the deputy
  against itself and delivered, where the agent's own open is refused `EACCES`, the deputy being undumpable
  (`PR_SET_DUMPABLE 0`). Only `self` and `thread-self` were translated to the task's thread group; an explicit numeric
  deputy pid was not caught. The walk now refuses any lookup landing in the deputy's own `/proc/<tgid>` tree with the
  agent's own errno, `EACCES` (`execWalk.inDeputyProc`, keyed on the deputy's `os.Getpid()`, threaded in through
  `DeputyPinner`/`walkAs`), which `pinHeld` returns as the kernel's answer (`heldAnswer`, no `held-*` line). The
  deputy's `/proc/<tgid>` directory itself, reached with no further component, stays (A); the plain world-readable
  entries (`status`, `stat`, `cmdline`) are refused too, a deliberate over-refusal that is never more permissive than
  the agent's own. A host probe confirmed the kernel's answers for a same-uid non-ptracer of an undumpable process
  (`status`/`stat`/`cmdline` readable; `mem`/`environ`/`auxv`/`maps`/`fd/N`/`cwd`/`exe` `EACCES`). Tests:
  `TestDeputyWalkRefusesItsOwnProc` (unit: the real walk refuses the deputy's own entries and reaches the task's own)
  and `TestHeldOpenCannotReachTheDeputysOwnProc` (integration: a real undumpable deputy under a read gate; without the
  guard it delivered its own `maps`, `fd/0`, `cwd` and `exe`, the `mem`/`environ`/`auxv` reopens already `EACCES` by
  the kernel's self-attach check). The residual this note first named, a magic link whose target already lies in the
  deputy's tree, the agent can arrange, and a later note closes it. Rejected: per-entry `ptrace`-gate emulation
  (fragile across kernels and entry sets, and the blanket refusal is never more permissive); comparing the pinned
  procfs inode's owning task (the inode number does not carry the pid reliably).

*2026-10-17, Stage B:*
- **A pin that lands in the open deputy's own `/proc` tree through a descriptor is refused too (amends D4's
  `/proc/<deputy-pid>/…` row).** The guard looked only at the directory each component was looked up in, so a magic
  link as the walk's last step landed in the tree unchecked. A run process can arrange that: an `O_PATH` open is never
  held and the kernel lets any process look the deputy's entry names up, so it holds an `O_PATH` descriptor of
  `/proc/<deputy-pid>/maps` (or `environ`, or the `fd` directory) and makes a held open of `/proc/self/fd/N`; the
  deputy followed the link, reopened its own entry and delivered it. Shown on the host before the fix: the real
  undumpable deputy delivered its own `maps` and `fd` directory (`TestHeldOpenCannotReachTheDeputysOwnProc`'s new
  `*_by_fd` cases). Every pin's end is now checked (`landsInDeputyProc`): a directory strictly below the deputy's
  `/proc/<tgid>`, or a procfs object of any other type whose directory is that one or below it (found by the deputy's
  own `/proc/self/fd` view of the pin and verified by inode under its name; unverifiable is refused), is `EACCES`; the
  deputy's directory itself stays (A). The same check covers an `AT_EMPTY_PATH` pin, and the leaf lookup an
  `O_CREAT|O_EXCL` or trailing-slash `O_CREAT` pin makes in a parent it walked to is refused there like the walk's
  own (an `EEXIST` or `EISDIR` the kernel gives there is `EACCES`, within the row's deliberate over-refusal). The class
  went further: the guard compared each directory with the deputy's own `/proc/<tgid>` by inode *and mount*, so the
  deputy's entries on a second procfs instance or a bind mount of `/proc` were reached, and anything it could not open
  was "not the deputy's". It now climbs to the root of the directory's own procfs mount and compares by inode with that
  instance's `self`, which procfs computes from the caller, the deputy; a mount of part of a procfs has no instance root
  to ask and is refused, as is anything the climb cannot open or stat. The pin's `PinLink` mode, which looked a final
  component up in a walked parent with no guard and which no caller asked for, is deleted. Tests:
  `TestDeputyWalkRefusesItsOwnProcByDescriptor` (unit: the deputy's `environ`, `mem`, `status`, `fd`, `task`,
  `task/<tid>`, `task/<tid>/environ` and `net/dev` reached through a run process's descriptors are `EACCES`; its
  directory, `/proc/sys` entries and plain files are reached), the leaf cases in `TestDeputyWalkRefusesItsOwnProc`,
  `TestDeputyWalkRefusesItsOwnProcOnEveryMount` (root, in KVM: a second procfs instance, a bind mount of `/proc` and a
  bind mount of the deputy's own directory), the three `*_by_fd` cases of `TestHeldOpenCannotReachTheDeputysOwnProc`
  (a real deputy under a read gate), and two differential shapes, `proc_file_by_fd` and `proc_dir_by_fd`, which hold a
  procfs file and directory outside the tree, reached through a descriptor, to the kernel's answers (397 shapes in
  all; with the parent's verification failing they are `EACCES`, so they show the real deputy places such a landing).
  Each fails without its check. The held
  hot path is untouched: a regular-file held open resolves in `pinInRun`'s single `openat2`, which never returns a
  procfs object, so the walk's one added `fstatfs` at its end is paid on the walk alone. *Corrected by a later
  note:* comparing with `self` knew the deputy only by its leader's directory, and missed the `/proc/<tid>`
  directories of its other threads.
- **Refuted: the walk applies `fs.protected_symlinks` to a trailing link only, as the kernel does.**
  `pick_link` (fs/namei.c, v6.17) calls `may_follow_link` under `WALK_TRAILING` alone and makes the nosymfollow check
  for every link, which is `followFacts.mayFollow`'s split. Kernel evidence, not argument: the root differential suite
  (`TestHeldOpenDifferentialAcrossMounts`, a non-root agent, the sysctl set to 1) has the kernel's own open follow an
  intermediate link of another owner in a sticky world-writable directory (`protected_symlink_mid`: the file's data)
  and refuse the same link as the final component (`protected_symlink_foreign`: `EACCES`), and the held open answers
  alike, in KVM on both boots. No change but the comments that say so.
- **A miscounted anomaly** (`TestHeldPinTheTaskLeftIsNoAnomaly` counted R22's 200 µs soft-ceiling anomaly as a deputy failure) was
  fixed earlier; re-verified under load.

*2026-10-17, Stage B:*
- **A held open cannot reach the open deputy's own entries through one of its other threads' `/proc/<tid>`
  (amends D4's `/proc/<deputy-pid>/…` row and an earlier note).** procfs looks any thread id up at its root, and
  `/proc/<tid>` of a thread other than the leader is a directory of its own, with its own inode, whose entries ask
  `ptrace_may_access` about that thread, which the deputy, of the same thread group, always passes. The guard
  compared the pin's directories with the instance's `self`, the leader's `/proc/<tgid>`, alone, so a held open of
  `/proc/<deputy-tid>/{maps,exe,fd}` was pinned and delivered by the real undumpable deputy (a Go program with
  several threads, `GOMAXPROCS=2`), where the agent's own open is refused `EACCES`; the agent finds such a tid by a
  stat of `/proc/<deputy-pid>/task/<n>`, which is never held. Shown on the host before the fix: the new
  `deputy_thread_*` cases of `TestHeldOpenCannotReachTheDeputysOwnProc` had the deputy deliver its `maps` (by name,
  under `task/<tid>/` and through a descriptor), its `exe` (ELF bytes) and its `fd` directory (by name and through a
  descriptor), 6 of 7 (`environ` was `EACCES` by the kernel's own check); the unit tests' 28 new deputy-thread cases
  all failed (26 pinned, and the two leaves answered `EEXIST` and `EISDIR`). `deputyProcDepth` now keeps the directory right under the procfs root as it climbs, the pid directory
  the tree hangs from, and calls it the deputy's when its `task/<n>` exists for `n` the instance's `self`: that
  lookup (`proc_task_lookup`) finds a thread id only within the directory's own thread group, so it answers for the
  leader's directory and every thread's, in that instance's own pid numbering; `ENOENT` is another process's
  directory or no pid one, and any other answer is refused as unsure. The thread's directory itself stays (A), as
  the leader's is; every route that used the guard (each lookup, a magic link or `AT_EMPTY_PATH` landing, the Excl
  and trailing-slash leaves, other procfs mounts) is fixed with it. The same leader-only comparison sat on the task's
  side in `ownMagicDir`, the exec walk's test for links the kernel follows for the task with no ptrace check: a
  magic link under `/proc/<task-tid>` was an unsure step (an errno, never a grant: fail closed), and now counts as
  the task's own. Tests that fail without the fix: deputy-thread cases in `TestDeputyWalkRefusesItsOwnProc` (by
  name, `task/<tid>/…` under the thread's directory, and the Excl and trailing-slash leaves),
  `TestDeputyWalkRefusesItsOwnProcByDescriptor` (through a magic link and, new for every case there, an
  `AT_EMPTY_PATH` pin), `TestDeputyWalkRefusesItsOwnProcOnEveryMount` (root, KVM: a thread's directory on a second
  procfs instance and a bind mount of `/proc`), the seven refused `deputy_thread_*` cases of
  `TestHeldOpenCannotReachTheDeputysOwnProc` (with one reached, the thread's directory itself, so the refusals are the
  guard's and not every procfs lookup failing under the deputy's filter), and `TestOwnMagicDirKnowsEveryThread`. Cost: the walk's procfs check
  trades an `openat` and `fstat` of `self` for a `readlinkat` of it and one `fstatat`; the held hot path, which
  never reaches a procfs object, is untouched. Rejected: listing the deputy's threads once at its start (Go starts
  threads at any time, and a list goes stale); comparing a candidate's `status` `Tgid:` line (a read the deputy's
  filter does not allow, and racy against pid reuse where the task lookup is answered by the kernel at the lookup).

**2026-10-20 (ADR 0007's second 2026-10-20 note).** Step 4 and the 2026-10-16 read-gate fix scored
the end of a rename or hard link that leaves its name, and an open that reads and writes, with the read predicates as
well as the write ones, "the stronger verdict kept". ADR 0007 now records that the scores of every rule an action
matches sum, and keeping the stronger of two kinds' sums is the highest-rule reading it rejects, between kinds. Both
kinds now score such an end as one action (`gate.Action.Reads`, every matching rule once, the scores summed), in
`scoreOpen` (so in `gateOpen`, both held-open paths, a held `fs.ask` write's target and an alternate) and in `gateFS`;
the two ends of a move stay two actions, the stronger kept. Held completion counts a read-write open as escalating
when the two kinds' rules together can reach `allow` (`openMayEscalate` over `gate.Policy.MayEscalateReadWrite`), and
D7's cells list the read-move, write-open and write-mutation cells for rules that escalate only together. Tests:
`TestGateSumsReadAndWriteKindsOfOneEnd`, `TestBestEffortCellsAreDisclosedAtCompile`'s two "only together" cases.

**2026-10-20 (ADR 0007's third 2026-10-20 note).** The two ends of a move are no longer two
actions: `gateFS` scores a rename or hard link as one action over both ends (`gate.Action.Dest`, `DestReads` under
`RENAME_EXCHANGE`), every rule that matches an end it scores counted once and the scores summed, so a read rule on
the source and a write rule on the destination add up. The best-effort cells, held completion and `MayEscalateReadWrite`
are unchanged: the rules one move can match are still a subset of both kinds' rules. Tests:
`TestGateMoveCountsEachRuleOnceAcrossItsEnds`, `TestGateSumsReadAndWriteKindsOfOneEnd`.

**2026-10-20.** Step 4 scored the end of a move that leaves its name by that name alone, so
it closed the bypass for a file and left it open for a directory: a move renames every file beneath the directory
moved, and `fs.read matches` with a separator matches a whole path (from the worktree, for a relative pattern). Under
`fs.read matches "work/secrets/*": 90`, `cat work/secrets/key` was refused, `mv work/secrets work/public` was continued
at score 0 and `cat work/public/key` read the secret: the same deterministic bypass the table above names, reproduced
at tier landlock. A read rule whose pattern holds a separator now also matches such an end when the pattern can match
a path beneath it (`gate.holdsMatch`: the pattern run as an automaton in `filepath.Match`'s own grammar over the
end's path and a separator, a class that holds the separator included), and, for a relative pattern, when the end is
the worktree or holds it, which renames every relative path. Options weighed: (1) disclose it in the
`gate.fs.read/move` cell and R1, rejected because the cell discloses a race on the copied name, not a bypass with no
race; (2) match the pattern's leading components against the end's one by one, rejected because a class may match
the separator (`x/s[^x]k` matches `x/s/k`), so the components need not line up; (3) the automaton, chosen: it never
misses a directory `filepath.Match` would match a path beneath (its differential test, ASCII only; both replaced the
same day, see the next note below). The
gate is handed no file type, so any end is taken to be a directory and the move of a regular file named as the
pattern's directory is scored too; a name-only pattern scores no directory's move, since the base names beneath it
stay. A hard link's source cannot be a directory, and is scored the same way. Tests:
`TestGateReadMatchesScoresAMovedAncestor`, `TestGateReadMatchesScoresRenameAndLinkSource` (three directory cases),
`TestCompileTestGateScoresAMovedDirectoryOfAReadPattern`.

**2026-10-20 (correcting the note above).** Option (3)'s automaton stepped a rune at a time
where `filepath.Match`'s star skips bytes, so it missed a directory whose name holds a multibyte rune: under
`fs.read matches "work/*[가-힣]/key": 90`, `mv work/é work/x` was continued at score 0 and `cat work/x/key` read the
secret, reproduced at tier landlock; "it never misses" held for ASCII names only. Option (2)'s objection is answered by
refusing it instead: [ADR 0007](0007-gate-only-escalates.md)'s fourth 2026-10-20 note reads an `fs.read matches`
pattern holding a `/` as component globs, refuses a class that can match `/` (and an escaped `/`) in such a pattern,
and matches both a path and a move's end one name at a time with `filepath.Match` itself, so the leading components do
line up; the automaton is deleted.

**2026-10-20 (the end's file type).** The earlier note took every move's end to be a directory,
since the gate was handed no file type, and said only that a regular file named as the pattern's directory is scored
too. Its reach was wider: under a wildcard directory component every move at that depth scores the rule, so under
`fs.read matches "*/.env": 90` `mv notes.txt notes.bak` and an editor's atomic save `rename(.out.json.tmp, out.json)`
were refused, and under `"/home/u/.config/*/token"` so was every atomic save in `~/.config`. A regular file has
nothing beneath it. Options weighed: (1) keep taking every end to be a directory and disclose the reach in R1 and the
CHANGELOG, rejected: it refuses ordinary saves under a pattern a careful author would write, and the fact that ends
it is at hand; (2) hand the gate the end's type, chosen: the decision stats the end it landed (`FinalIsDir`, fstatat
with `AT_SYMLINK_NOFOLLOW`, the stat `referRefuses` already makes for REFER) when a read rule is a path pattern
(`Policy.ScoresBeneath`), the source and, under `RENAME_EXCHANGE`, the destination, and an end found to be no
directory (`gate.Action.PathNotDir`, `DestNotDir`) is matched by its own name. A stat that fails otherwise than with
`ENOENT` leaves the type unknown, read as a directory. The narrowing keeps the closure that note made: between the stat and
the kernel's move, the name can come to hold a directory a pattern reaches beneath only through a move of that
directory, whose own source the gate scores where the directory stands; a name a peer re-points between the walk and
the kernel's lookup is the copied-name race the `gate.fs.read/move` cell already discloses. `compile --test` reads a
move row's object as a directory when it exists as one or the row says `dir: true`, as ADR 0043 reads it. Tests:
`TestGateMoveOfANonDirectoryIsMatchedByItsName`, `TestGateReadMatchesScoresRenameAndLinkSource` (an atomic save, a
regular file's move and an exchange of two at a wildcard's depth continued; a failed stat scored),
`TestCompileTestGateScoresAMovedDirectoryOfAReadPattern`.

**2026-10-20 (ADR 0007's first 2026-10-20 note).** A score of exactly `allow` now
asks, as ADR 0007's bands read, so `MayEscalate(kind)` counts from `allow` inclusive: where D1's rule 1 says a kind
"cannot reach a score above `allow`" and Step 8 says `MayEscalate` uses the subset-sum "with `> allow`", read "cannot
reach `allow`" and "with `>= allow`". A kind whose rules can sum to exactly `allow` is now held under `completion:
held`, opens its (D) cells and needs the deputy, as `Evaluate` asks there (`TestGateThresholdBoundaries`
checks `MayAsk`/`MayEscalate` against `Evaluate` at 49, 50 and 51).

**2026-10-26, a UDP connect that sends nothing stays refused (D6).** Under a
contract (`net.allow` naming `tcp://chatgpt.com:443`) a Codex run's ledger holds hundreds of refused UDP connects to port
65535 of the addresses its lookups return: musl's `getaddrinfo` connects a UDP socket to each answer and reads
`getsockname` to sort them (RFC 6724), and glibc's does the same on the service's port, then disconnects with
`AF_UNSPEC` (reproduced with Python under tier landlock: `udp connect` to 104.18.32.47:65535 and :443 fails `EACCES`).
The kernel sends nothing at a UDP connect, so the question was whether to admit it as a lookup probe. It stays
refused. The connect is the only decision such a socket gets: once connected, `write(2)`, `send(2)` and an unaddressed
`sendto`/`sendmsg` reach the peer with no decision of their own (supervisor R13a: decided once, at `connect()`), so admitting the
connect admits every later datagram to that address and port. Admitting it only for an address a host entry resolved
is no better: an entry's protocol and port would stop meaning anything for UDP, and QUIC on 443 to an admitted host
(a `models[]` host under `capture: forwarder` among them) would reach it around the forwarder and the HTTP policy.
Answering success without connecting invents a result (I3) and leaves a socket whose sends fail `EDESTADDRREQ`. The
cost of refusing, measured: outside tego the IPv4 probes succeed and the IPv6 one fails `ENETUNREACH` on a machine with
no IPv6 route, so glibc returned chatgpt.com's IPv4 addresses first; under tego every probe fails, and it returned the
IPv6 ones first. Codex likewise connects IPv6 first, each failing `ENETUNREACH` in the relay: 365 IPv6 connects to
chatgpt.com for 184 IPv4 ones in one ledger. What changed is display only: the dashboard folds a
route probe as background, and a route probe is now UDP to port 65535 of a remote host (`ledgerview.RouteProbe`); a
TCP connect to that port, which the port alone used to fold, is a real attempt and stays on top
(`TestRouteProbeIsAUDPConnect`). The IPv6-first cost stands, and no ledger mark yet tells a UDP connect from a UDP send.

## Later decisions

*Amended 2026-10-05 (D1 decided: (a)):* D1 is decided
**(a)**: at tier landlock and at tier cgroup without a plane (L, C⊘) the built-in `deny_write` cells are (D) by
default, disclosed best effort, and a contract opts in to the strict refusal. The reasons:
- It restores the semantics decided before the 2026-10-03 change: the supervisor's refusal of the targets (supervisor R15c),
  "best effort, not a closure" (SEMANTICS §2), with an `unenforced` warning. That change was made by spec text alone,
  with no ADR; ADR 0040 recorded the change afterwards.
- It matches `deny_read`'s handling below Landlock's reach: a `deny_read` nested in a write entry, which tier 1
  cannot hold, warns `unenforced` and runs. ADR 0040's stated asymmetry between the two is gone.
- It keeps an unprivileged git-worktree run possible (tier landlock is the only tier without root, and the only one
  on a host without BPF LSM) with honest disclosure: one compile warning per target and run_start `best_effort`
  `deny_write/default`. Fail-closed stays available through the opt-in.

(b) and (b+) were not chosen: both keep as the default a launch refusal no ADR decided, which fails the commonest
coding-agent contract at the only unprivileged tier, and ask every such user to write an opt-out to get back the
earlier behaviour.

The opt-in departs from D8's (a) column in its shape. It is `fs.assurance: best-effort | kernel` (default
best-effort), not a top-level `assurance:`. D8 put it at the top level so that it would also refuse every (D) gate
cell, but by D1's table the `fs.write` and `exec` gate cells are (D) at every tier, so a top-level `kernel` could
never be met by a contract with such a gate, and it would answer two questions with one key. The gate cells stay
disclosed by D7 alone; `fs.assurance` governs the built-in `deny_write` cells only and mirrors `net.assurance`.
D8's merge rule is kept: across `extends` the stricter value wins, and a file's `best-effort` that a profile's
`kernel` outvotes is warned (`redundant-rule`). D8's run_start `assurance` field is not added: under `kernel` a run
that starts always has a plane deciding its targets, `best_effort`'s `deny_write/default` names the lowered state,
and contract_hash carries the key. Under `kernel` the compile error D8 specifies at a pinned or machine-held tier
landlock applies, and a run no plane decides exits 125 with the fix (enforce-landlock R5a, agent-contract R20). A
tier with a plane mode, and tier bpflsm, decide the targets in the kernel either way; their behaviour is unchanged.

ADR 0040 (1), the unconditional launch refusal, is superseded by this note; ADR 0040 says so.
*Amended 2026-10-16 (D1's unix rows, supervisor R11 and R11a):* a refinement that keeps D1's outcomes — the unix
connect (A), relayed; the addressed unix datagram (D), never relayed — and states what those decisions are made on.
The principle above (a decision on copied arguments is completed in the run's own context or it is not a decision
about what the kernel will do) applies to where a name leads as much as to its bytes: a unix pathname was decided on
its lexically cleaned spelling, `stat`ed in this process's own view, while the kernel resolves the name for the task,
from its root and cwd, following its symlinks and its procfs magic links as the task. Earlier fixes patched the
cases one at a time (a `..` walked only when present, then a magic link reported) and each left the next.

Decision. **One walk for every unix name, in the task's view, and a decision on the identity of what it reaches.**
- *The walk* (`unixWalk`): the raw `sun_path`, never cleaned, opened `O_PATH` with `openat2` from `/proc/<tid>/root`
  with `RESOLVE_IN_ROOT` (absolute) or from `/proc/<tid>/cwd` (relative; a task whose root is not this process's
  refuses it), with `RESOLVE_NO_MAGICLINKS`. A lookup that fails as the task's may (`ENOENT`, `ENOTDIR`, `EACCES`) is
  walked again a component at a time (R16b's walk with magic links refused), which answers procfs's `self` and
  `thread-self` for the task, so the errno is the task's own and not what this process's pid directory holds; a
  walk that ends on procfs is refused; a connect whose name only that walk resolved is refused as well, since the walk
  reads symlinks rather than following them (it is not held to `fs.protected_symlinks`) and the relay connects to
  what it reached. The only links whose target depends on who follows them are procfs's `self`
  and `thread-self` and the magic links; with magic links refused, `self` leads nowhere but procfs or, through
  `..`, back up to `/proc`, the same climb for every pid, so a lookup that succeeds off procfs lands where the
  task's does. Credentials decide only whether a lookup may pass, never where it lands: a datagram's and a bind's
  walk use this process's, the connect relay's the task's (R11).
- *The place*: the reached inode's path read back and walked again in this process's view following no symlink
  (`sameInodeHere`), so a policy path, written in this view, can be matched against it; a place this process cannot
  see at the same inode is refused.
- *A connect* (A): unchanged — the relay connects to that inode through `/proc/self/fd/<n>`. *A datagram* (D):
  matched by that socket's place against each declared entry's resolved path and the write entries (`decideResolved`,
  the relay's own match) and through a write entry only when the run bound it (R11a), after its name passed the
  name-level match the kernel programs make; the kernel's second lookup after `CONTINUE` stays the disclosed (D)
  residual. A name the walk cannot resolve is refused, never continued: `path-unreliable`, or `unix-absent` with the
  lookup's errno.
- *A bind* records the socket's identity with the bind's name (the bytes the kernel keeps) and the device of the
  directory the walk reaches, every component but the last followed (`kern_path_create`). Which recorded bind took is
  the kernel's to say: it reports the name a socket is bound by (`UNIX_DIAG_NAME`, in the lookup that reads its file),
  and the directory is that bind's. A socket bound by a name no recorded bind passed is not attributed to the run
  (`unix-bind-unrecorded`); its directory is unknown when a bind of that name could not be walked, when two reached
  different directories, or when the name is relative and a bind whose socket could not be read came first, and an
  unknown directory refuses where it decides (btrfs, overlayfs: `unix-origin-unread`). Where `st_dev` is the
  superblock's, the superblock and the inode number settle the file and the directory is not asked.

What it closes, with a test that failed before it: a symlink at a declared name (the datagram reached a socket outside
every entry under that entry's `allow`), a `..` after a symlink and a `/proc/self/cwd` link (datagram and bind), a
declared entry reached through a symlinked directory by a `..` name (refused before), a second bind after a failed one
(the first's directory kept), a bind's address rewritten by a sibling after it was read and a descriptor swapped after
it was duplicated (the read name recorded as what took), and a bind not walked or not read before or during another's
record. What stays disclosed (supervisor R11a residual (4)): on btrfs, the run changing the filesystem between this
loop's walk of a bind's name and the kernel's (a renamed directory, a swapped symlink, a `CLONE_FS` cwd change), so
the same bytes land in another subvolume; R13b's datagram race, unchanged. The conditions that close them are the
plane's peer check (step D) and, for the bind at the root tiers, `SIOCUNIXFILE`.

Rejected: `stat`ing the cleaned spelling (the defect); walking only names with a `..` (missed magic links and a
symlink at a declared name); R16b's component walk for every name, which follows the task's own magic links where the
relay refuses them, so a connect and a datagram to one name could be decided apart, at a descriptor per component;
relaying the datagram (rejected in D1: the receiver would read this process's credentials); for the bind, keeping the
first record, unsettling a socket whose binds named two devices (refused the run's own retried socket and stayed blind
to a rewritten address), refusing every later socket where the subvolume decides once any bind went unread (one
`ssh-agent` makes that permanent at tier landlock), binding in this process (outside the task's Landlock domain,
credentials and umask), taking `UNIX_DIAG_NAME` as proof of a file's identity (a name the run controls; it only
chooses among the run's own recorded binds and refuses one that is none of them), and `SIOCUNIXFILE` everywhere
(`CAP_NET_ADMIN`: the root tiers only). Cost: one walk per name per notification, 25 to 39 µs on the test machine under load
(`BenchmarkUnixTarget`), against the one `statx` it replaces; the package's own work per notification is unchanged
(`BenchmarkNotificationRoundTrip`, `BenchmarkSendMMsgTail`). Separately, `TestUnixForeign` failed as
root: a supervisor holding `CAP_SYS_PTRACE` passes `ptrace_may_access`'s dumpable
check, reads a non-dumpable child's bind and records its socket, which is the run's own; the refusal the test
expected is an unprivileged supervisor's, and the test now expects each by the capability it runs with.

*Amended 2026-10-17:* the 2026-10-16 note above over-stated what the kernel's reported name settles. `UNIX_DIAG_NAME` is the raw
`sun_path` bytes, not where they resolved, so attributing a bound socket's **directory** by matching those bytes to a
recorded bind is sound only when the bytes resolve to one place. They do not when (a) the reported name is relative —
it resolves from the binding task's cwd, which the kernel does not report, so a sibling that rewrote this socket's
address to the reported bytes, a descriptor swapped onto it, or a second process of the run resolves the same bytes
from another cwd and lands elsewhere; or (b) a bind of the run went unread — it may have taken this socket by a name
the loop does not know, from a cwd it does not know, or (absolute) through a symlink changed after the record's walk.
The 2026-10-16 rule trusted a relative name's recorded directory when no bind had gone unread, and an absolute name's
always, so each of those admitted a foreign socket repeating the run's inode number in the recorded subvolume on
btrfs. The rule is now: **a bound socket's directory is attributed only when no bind of the run went unread
(`unknownBinds == 0`), every record of the reported name was walked to one device from one cwd, and — for a relative
name — the same bytes could not have resolved from another cwd (this socket has no other recorded bind from a cwd
other than the matched record's, and no other socket not yet seen bound recorded that name from another cwd,
`relNameFromOtherCwd`).** Each bind's cwd identity (the task's `/proc/<tid>/cwd`) is recorded with it, so a second
bind after a failed one from one cwd settles — the reported name resolves alike from that cwd whichever took — while
binds across two cwds (a rewrite, a descriptor swap, a shared socket) do not. A single relative bind from one cwd
settles too (a `multiprocessing` or MCP socket bound by a relative path, as `TestIntegrationUnixRelayOnBtrfs` binds
`b/own.sock`, `TestIntegrationUnixRelayRebindOnBtrfs` the second-bind case); it is the two-cwd shapes that leave it
unknown. An unread bind leaves even an absolute name's directory unknown. All of these fail closed to
`unix-origin-unread` where the subvolume decides, and on ext4/xfs/tmpfs the superblock and inode number still
settle the file. This corrects "a bind's address rewritten … and a descriptor swapped … (the read name recorded as
what took)" in the "What it closes" paragraph: a rewrite or swap onto bytes the socket itself recorded is now treated
as that record and so refused where its directory is unknown (a relative name whose bytes another cwd could reach,
any name after an unread bind), and admitted only where the record's directory is certain (an absolute name with no
unread bind, a relative name bound from a single cwd) but for a filesystem change (residual (4)); a rewrite or swap
onto bytes no record carries stays `unix-bind-unrecorded`. It also moves
"refusing every later socket where the subvolume decides once any bind went unread" from the rejected list to the
accepted design: it is the chosen fail-closed rule, with the disclosed cost that one `ssh-agent` at tier landlock
refuses the run's own btrfs or overlayfs sockets under a write entry for the rest of the run. A per-socket count of
unread binds was rejected as unsound — an unread bind counted before a socket's record can still take it afterwards,
its kernel bind landing after `CONTINUE`. Closed with `TestBindRecordsTheDirectoryTheKernelBindsIn`'s (replaced since) rewrite,
descriptor-swap, absolute-symlink-after-unread and absolute-after-unread cases, each admitting the foreign socket
`allow/fs.write` before the fix.

*Amended 2026-10-17:* both notes above attributed a bound
socket to a **directory** by its bind's name, and a foreign btrfs socket was admitted again through
orderings neither rule saw: a bind this loop continued with no record — an address read as abstract or as
`AF_INET`, a descriptor of a socket bound already, a full set — taking the socket with bytes matching its own earlier,
failed record; a rewrite or a descriptor swap onto a recorded name after a symlink was changed at leisure, which needs
no race against any walk; a swap whose other socket, the record of the other directory, was gone or bound since.
That is three rounds of one class. A name predicts where the kernel's lookup will land, and the prediction is the
run's to defeat: a swapped descriptor makes every bind notification, an IP one included, a possible taker of any of
the run's sockets bound to nothing, by bytes copied after `CONTINUE`.

Decision. **The run's sockets are socket objects, and a file is decided to be one's by identity; no bind's name,
directory or cwd is recorded or trusted.**
- *Ownership.* A socket the run bound is one a task of the run held, bound to nothing, and called `bind` on: its
  sockfs inode and `SO_COOKIE` on the duplicate (as before), and when each bind of it was answered. A socket bound
  already is not recorded (its bind fails `EINVAL`). Which bind took, with which bytes, from where, does not change
  whose object it is. A descriptor swapped after the duplicate leaves the duplicated socket recorded — still one a
  run task holds — and the socket the kernel bound unrecorded, refused: fail closed, granting nothing the task could
  not already do with its own descriptor.
- *The file, where `st_dev` is the superblock's* (ext4, xfs, tmpfs): the superblock and an inode number that fits
  `UNIX_DIAG_VFS`'s 32 bits are one live file, as before (`ownsFile`).
- *The file, where `st_dev` is not the superblock's* (btrfs subvolumes, overlayfs layers), whose files share
  (superblock, inode): the file the agent's name reaches (pinned by the relay, walked once for a datagram) is the
  socket's only when (a) its birth time (`STATX_BTIME`, which no `utimensat` sets) lies within 50 ms before and ten
  seconds after one of the socket's recorded binds and no later than the socket was first seen bound — a socket bound
  to nothing when its bind was recorded makes its file after, and one seen bound made it before — and (b) no socket
  outside the run shares the pair in a dump of the network namespace's unix sockets (`NLM_F_DUMP`, `UDIAG_SHOW_VFS`)
  begun after the file was reached or more than a second after the file was born (the kernel's bind makes the file,
  then hashes the socket), connected stream and seqpacket sockets excepted (an accepted one reports its
  listener's file, and neither it nor a bound socket that connected is reached through a file). A file born before the
  first recorded bind or after the socket was seen bound is not its file; a birth in no recorded bind's window, an
  unknown birth time, a shared pair, a dump refused or past 65,536 sockets, and a notification past 16 dumps refuse
  (`unix-origin-unread`), fail closed. The dump is taken only there, after (a) admits, which bounds the cost R11a's
  2026-10-16 bounded-work rule rejected a dump for.

What it closes, each shown admitting the foreign socket `allow/fs.write` before this change and refused `unix-foreign` now,
with the run's own socket admitted (`TestR11aDecidesTheBoundFileByIdentity`): the six orderings of a bind and a rename, the
rewrites and swaps (C), (D), (E), the gone and bound-since swaps, and every earlier ordering (a `..` after a symlink, a magic link, a second bind after a failed one, two cwds). The cost
goes with `relNameFromOtherCwd`: one sweep that first sees 256 sockets bound is 0.76 ms of the fake kernel's
(`BenchmarkR11aSweepSettles`) where an earlier measurement read 58 ms. Race tests: the relayed connect against a
sibling swapping the last component's symlink, a directory's symlink, and a directory a `..` climbs from, moved to
another parent or renamed (`TestConnectUnixAsUnderSwapsConnectsOnlyTheInodeAdmitted`), and the bind's `sun_path`
rewritten while it runs (`TestBoundFileIsBornInItsBind`). What stays disclosed, as supervisor R11a residual (4) now:
a socket a process in **another network namespace** — which this namespace's dump does not list, while a pathname
socket is reached from any — binds on the same btrfs or overlayfs superblock, in another subvolume, during one of the
run's binds (its file born in that window) and at the run's socket's inode number, or a process in this namespace
binds so with its bind under way while the dump is read (the file made, the socket not yet in the table). The run
cannot make a network namespace (E24), cannot pace a process outside it, and needs such a process to bind on cue at
a number it arranges. The plane's peer check (step D)
closes it, as it closes (1) and (2).

That proposal, evaluated. Adopted: ownership by the socket object, dropping the directory attribution, the
cwd records and `unknownBinds`, and the namespace's dump. Refuted as written: (i) "candidates are the dump's sockets
bound by the pinned file's pair; every candidate the run's means the target is" — `sock_diag` dumps the asking
socket's network namespace only, while `unix_find_bsd` finds a pathname socket in the kernel's table of bound
sockets whatever its namespace, so a foreign socket in another namespace colliding with the run's would be admitted;
the birth time is what covers it, save (4); (ii) "no candidate means a stale file, which the kernel refuses itself" —
it can also be a live socket of another namespace, so no candidate refuses here, by the R11a rule that a file no
socket of the run's is bound to is not admitted; (iii) "any candidate not in the set refuses" — an accepted
connection reports its listener's file, so a listener of the run's with one connection open would be refused;
connected stream and seqpacket sockets are left out of the dump for that, which is sound because no connect or
datagram reaches them through a file; (iv) the superblock's device from mountinfo is what owns already used, and
mountinfo's third field on btrfs is `sb->s_dev` (`TestUnixBoundOnBtrfs` checks it against `UNIX_DIAG_VFS`); (v) the
overlayfs `xino` case: there the overlay's inode numbers are not the upper file's and `st_dev` is the overlay's own,
so `st_dev` is the superblock's and the pair is exact (`ownsFile`), not a refusal.

Rejected: (1) keeping the directory attribution as a further condition with more accounting
(every continued bind counted, a run-wide index of names to directories never pruned, a socket with two names
unknown) — a sound count refuses every btrfs socket once the run has bound an IP port, and the birth time already
refuses the pre-existing sockets the attribution was there for; (2) binding in this process on the duplicate, which
would make the directory certain but either stores this process's spelling as the socket's name (a pinned parent's
`/proc/self/fd/<n>/<name>` or the bare final component: `getsockname` and the peers' view change, and
`multiprocessing` hands its children the listener's `getsockname`) or resolves the task's bytes again, and takes the
bind out of the task's Landlock domain, credentials and umask; (3) `SIOCUNIXFILE` at the root tiers, which needs a
descriptor of the socket once it is bound — one kept from the bind keeps a socket the run closed bound and
connectable, one found again in the run's descriptor tables is a scan per socket — and which tier landlock cannot do,
so the tiers would decide one socket apart; (4) a probe connect, or `SO_PEERCRED` and `UNIX_DIAG_ICONS` after the
relayed connect, which put a connection into the run's or a daemon's listener before the decision; (5) `ctime`
instead of `btime` (a link, a rename or a `chmod` by the run under its write entry moves a foreign file's); (6) the
birth time against the run's start (supervisor R11a's rejected option (2), still rejected: an outside process's socket
made during the run would pass it, and is in this namespace's dump here). Cost: a bind walks nothing now; where
`st_dev` is the superblock's nothing is added; elsewhere a decision the birth time admits pays one dump per
notification for the files it reached before the dump, 0.18 to 0.27 ms for 932 sockets on the test machine at load 16
(`BenchmarkUnixDump`); `BenchmarkNotificationRoundTrip`, `BenchmarkSendMMsgTail` and `BenchmarkSendMMsgForeignUnix`
are unchanged in bytes and allocations (`scripts/bench-gate.sh`, six alternating rounds, no finding). This note
corrects the two above: no bind's name is attributed, `unix-bind-unrecorded` no longer names a rewritten address or a
swapped descriptor (both are the run's own socket now, or refused by identity), and an unread bind no longer refuses
the run's own btrfs or overlayfs sockets.

*Amended 2026-10-17:* (b) above took
one `NLM_F_DUMP` as the namespace's whole list, and it is not one when the kernel sends it in several datagrams.
`unix_diag_dump` walks each hash bucket of the namespace's socket table whole under that bucket's lock, but starts
each datagram after the first at a saved (bucket, index) pair; a socket that leaves that bucket in between — closed,
bound, connected, or made at its head after the walk passed and closed again — shifts the sockets after it, and the
next datagram skips one that stayed bound throughout. A probe measured 5 to 16 of 12,000 missing per dump while
its own sockets closed between datagrams; `TestUnixDumpIsOnePassOrRefused` has 1 to 3 of 4,000 missing from 9 of 40
dumps while a sibling makes and closes unbound sockets. The run paces that churn, and its own colliding socket is in
the foreign one's bucket (a pathname socket is hashed by its inode number), so a foreign socket born in the run's
bind window at the colliding number could be the one skipped, and a relayed connect admitted it `allow/fs.write`:
same namespace, bind complete, neither residual. The note above's "a socket an outside process makes during the run
is in this namespace's dump" did not hold for such a dump.

Decision. **A relayed connect's dump is one pass of the kernel's walk, proved from what the kernel sent; a datagram's
is read whole and its skip is disclosed within the datagram's best effort.**
- *One pass.* Within one datagram nothing is skipped, so only a dump whose first datagram ended the walk is taken
  (`dumpNeed.onePass`): the dump socket first receives a reply with a 32 KiB buffer, which makes `netlink_dump` fill the
  dump's first datagram into `max_recvmsg_len` (`SKB_WITH_OVERHEAD(32768)` since Linux 4.6) rather than
  `NLMSG_GOODSIZE`; the receive queue's charge after the request (`SO_MEMINFO`, the datagram's truesize: 33,024 bytes
  for the large allocation on the test machine, 4,352 for a page) says which it got; the datagram must leave room for one more
  socket's message — `unix_diag_dump` stops a datagram only at a message that does not fit, 52 bytes with
  `UDIAG_SHOW_VFS` and the unconditional `UNIX_DIAG_SHUTDOWN`, bounded at 256 — and the next datagram must hold no
  socket. Otherwise `errUnixDumpSplit`, refused `unix-origin-unread`. Binding one socket at a time, the dump is refused
  while the kernel still sends the list in one datagram (the margin), and with the room check removed it is first
  refused only once the kernel has split it.
- *Which sockets.* A stream or seqpacket socket's connect reaches through a file only an unconnected listener of its
  type (`unix_find_other` refuses another type; a connected stream never listens, an accepted one is not in the bound
  table), so its dump asks for every state but `TCP_ESTABLISHED` (`needConnect`): connected streams are most of a
  desktop's unix sockets (some 830 of 950 here), and the rest fit one pass up to some 600 (69 here). A datagram
  socket's connect asks for every state — a datagram socket another socket connected to reads `TCP_ESTABLISHED`
  (`unix_dgram_connect` sets both ends), and still takes datagrams and connects from any — which a busy desktop takes
  past one pass, so such a connect on btrfs or overlayfs is refused there, fail closed.
- *A datagram* (`needDatagram`) reads the whole list, every state, in as many datagrams as it takes. Its decision is
  best effort whatever the dump says: the kernel looks the name up again when it sends, so a run swapping a symlink
  on the name reaches any socket without a collision (supervisor R11a residual (1)), and a socket the list skipped is
  named in that residual. Asking it for one pass would refuse the run's own btrfs datagram sockets on every busy
  desktop for no boundary the residual does not already lack.

Rejected: (1) a second dump that must list every socket the first one listed, which
narrows without closing: a socket the dump never lists shifts a bucket as well — one made at the bucket's head after
the walk passed and closed before the next datagram (7 to 12 skipped per 12,000-socket dump by churning only such
sockets, none ever listed), or a pending connection, which has no inode and is never listed, and goes when its
listener closes; (2) refusing when the dump took several datagrams while the namespace's count changed, since
churn keeps the count; (3) one pass of every state for every decision, which refuses every connect to
the run's own btrfs sockets on a desktop for sockets a stream connect cannot reach; (4) disclosing the skip for
connects too: the run paces its own churn, and a relayed connect is not best effort; (5) the
kernel's BPF unix socket iterator (`iter/unix`, which batches a whole bucket under its lock), at the root tiers only,
so tier landlock would decide one socket apart; (6) `/proc/net/unix`, whose reads resume by an offset within a bucket
in the same way and name sockets by the names they were bound with; (7) inferring a bucket's place in the dump from
pathname sockets' inode numbers (`i_ino & 255`), which rests on the kernel's hash layout and still leaves unbound and
abstract sockets' buckets unknown. What stays disclosed is residual (4) as the note above has it, for this
namespace's sockets now only a bind under way while the one-pass dump is read; and, in residual (1), what a
datagram's list skipped. Cost: the dump adds an exact request and a `getsockopt` before it; a stream connect's lists
the unconnected sockets only, 72 to 89 µs for 69 on the test machine at load 13 to 16, where a datagram's, every socket, is 193
to 218 µs for some 950 (`BenchmarkUnixDump`); neither is paid where `st_dev` is the superblock's.
`TestUnixDumpIsOnePassOrRefused`, `TestR11aConnectDumpIsOnePass` and `TestUnixDumpListsWhatAConnectCanReach` hold it.
This note corrects the one above: a relayed connect's dump lists every socket of this namespace that its connect can
reach and that was bound before the dump began and is still bound, save one whose bind is under way; a datagram's
may leave one out.

*Amended 2026-10-17:* `alone` admits only
when the dump lists one of the run's sockets under the pair, and the code said a dump listing none meant the socket
had gone. Since the note above, a stream or seqpacket socket's connect lists no connected socket, so the run's own
datagram socket that another socket connected to (`TCP_ESTABLISHED`) is left out of it too, as a connected stream
socket of the run's always was; such a connect on btrfs or overlayfs is refused `unix-origin-unread` where it was
admitted and met the kernel's `EPROTOTYPE`. Decision: **kept, and named.** A list that shows no socket of the run's
under the pair refuses whatever left it out — the socket closed, a datagram's list skipped it, or the list leaves it
out because it cannot take the connect (`errNotListed`) — and the kernel would have refused that connect too
(`ECONNREFUSED`, or `EPROTOTYPE` across types), so only the errno and the ledger's rule differ, and the rule's text
(`ruleUnixOriginUnread`, R11a, SEMANTICS §5, OPERATIONS) now says the list did not show the socket. Rejected: (1)
asking a stream connect for every state and leaving out by type afterwards, which brings a desktop's connected
streams back and takes the list past one pass, refusing the run's own listeners to spare a connect the kernel
refuses anyway; (2) admitting when the list shows no socket under the pair at all, which would write `allow` on the
run's own socket while the list showed none. The row "the run's own socket is connected" of
`TestR11aConnectDumpIsOnePass` holds it.

*Amended 2026-10-19 (the deadcode ratchet, ADR 0029 (4)):* the deputy's walk the Stage B Step 7 note names as
`supervisor.DeputyPin` is `supervisor.DeputyPinner`, which `tego __open-deputy` calls, over the unexported
`deputyPin` that now carries the D2 and D4 contract in its doc; `DeputyPin`, which only tests called, moved into the
package's test files. No behaviour changed.

*Amended 2026-10-25 (ADR 0069's part-3 note):* D4's one re-pin also takes a pin reached by a name
that names no inode, or another one, when this loop reads the pin (a rename over the file after the deputy's walk).
The 2026-10-16 entry on a gone name refused every such pin `gate.unreadable`; it is now pinned once more, as the task's own
open made then walks the name again, checked and scored on the second pin, and the second answer stands: a second
such pin is refused `gate.unreadable` where a gate scores the open, `held-unsupported` where it is held only as a
read. That entry's property, never decided on the copied name, stands (`TestHeldPinWhoseNameIsRemovedIsUnreadable`).
