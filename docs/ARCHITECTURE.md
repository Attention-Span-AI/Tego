# Architecture

Design baseline revised 2026-09-21 after the verification pass; current tier summary and implementation boundaries reconciled 2026-10-03. Facts marked (verified) were checked against kernel sources, man
pages, vendor documentation or this machine; the rest is design to be proven in `test/`.

This document combines implemented behavior and planned capabilities. `tego serve` hands off to `tego-control`, the local dashboard (docs/DASHBOARD.md); `learn` is built (2026-10-06, docs/OPERATIONS.md); additional provider parsers are not. For current implementation status, use `spec/backend/CAPABILITIES.md` and `docs/p0/TIER3-PLAN.md`; dated verification notes below retain their historical scope.

## 1. A run, in order

1. `tego run <agent> -- <cmd>`: `internal/cli/run.go` loads the machine config (spec/config/v0) and the contract
   (`pkg/spec/agent`), validates it with line numbers, and compiles it to rule tables for the tier the machine allows.
2. `internal/runtime.Run` creates the run cgroup (`cgroup`), opens the ledger, starts the supervisor goroutines, then
   re-execs the child stage (§5), which applies Landlock and the seccomp filter and execs the command with the
   identity environment set (`spec/identity/RUN-IDENTITY.md`). A `claude` command gains `--settings` with a per-run file,
   so refusals reach the agent through the harness hook (ADR 0063), and `--mcp-config` when the contract relays MCP
   servers. A root launcher, a run with no runtime directory, an allow-list contract that does not admit the hook, and
   `harness: none` leave the argv as given.
3. Kernel events (eBPF in the root tiers, the seccomp supervisor in the unprivileged tier), asks, and captured model
   traffic flow as `record.Event` values into `internal/ledger` (one write per line, hash-chained, redacted, bodies as
   blobs). `derive` turns bytes into decisions, steps and threads; `limits` watches budgets and stops the run through
   `cgroup.kill`.
4. Refusals reach the agent as the syscall error and, through `reason` and `internal/adapters`, as a reason string
   where the harness has hooks (`spec/reason/REASON-CHANNEL.md`). *As of 2026-10-18, of what the agent is told, only the
   syscall error is built:* `internal/runtime/reason` and `internal/adapters` are placeholders, and the reason code reaches the ledger
   and `$TEGO_REASON` only. *Amended 2026-10-24 (ADR 0061):* the
   `internal/runtime/reason` placeholder is removed; the reason file v1 and its wording are `pkg/spec/reason`, and
   `internal/adapters` reads it through that package (the claude-code provisioner and hook; other harnesses' hooks are not built).
5. `status`, `drift`, `measure`, `learn`, `events` and `serve` read the ledger and nothing else (`serve` through `tego-control`).

Two rules keep it clean: the engine never imports the read side, and the ledger is the only store.

## 2. Tiers

*Current implementation 2026-10-04 (ADR 0024; [enforce-plane](p0/enforce-plane.md), [Tier 3 plan](p0/TIER3-PLAN.md)):* tier 2 uses the kernel decision plane where doctor's probe selects `lsm` or `fmod_ret` (`bpf.plane` can pin a mode); otherwise its path-aware open/exec listener is the fanotify fallback. Tier 3 uses the plane in LSM mode and shares its semantics with tier 2. Steps A–D are built: path operations, create/metadata and socket policy, executable mappings, and Unix names below 6.7. T16's filesystem handover is enabled per loaded hook and a recorder that can name paths; its exec handover delegates policy and terminal outcomes when the plane and complete live kernel recording are ready, retaining notifications for metadata and supervisor fallback otherwise. The ledger records the selected `decision_plane` and per-run capabilities.

| Tier | Needs | Gives |
|---|---|---|
| 1 `landlock` | no root | inode-based filesystem allow rules, TCP restrictions, supervisor-mediated host/connect decisions, supported write-open and TCP-connect approvals through the bounded authenticated CLI broker; unavailable or unsupported completion mechanisms are refused, and seccomp recording; consult the capability matrix for ABI and topology limits |
| 2 `cgroup` | root or the required capabilities; no boot change | network rules in the owned run subtree, kernel recording and supported TLS uprobes, plus path-aware open/exec decisions through the probed plane or fanotify fallback; daemon/container adoption remains future product work |
| 3 `bpflsm` | tier 2 requirements plus a usable probed LSM plane | the built filesystem and executable-mapping plane plus declared Unix bind/listen and scoped ptrace/BPF/keyring controls; capabilities depend on the actual probed, loaded and attached hooks, as recorded for the run |

`observe` is a run mode (no enforcement, record only), not a tier. The runtime picks the highest tier at or below
the machine config's ceiling; the capability matrix (`spec/backend/CAPABILITIES.md`) is recorded on every run.
Support by distribution is in §14.

## 3. Process trees, resources, nested runs

**Many processes in one run.** Identity is the cgroup; everything the agent forks or execs stays in it. Landlock and
the seccomp filter are inherited across fork and exec (verified), and every BPF map is keyed by cgroup id. Threads
inside one process are attributed by tid and by the model-traffic thread derivation.

**Nested runs.** An agent that runs `tego run` for a sub-agent gets a child cgroup and `parent_run` from the
inherited `TEGO_RUN_ID`. Policies compose: allow lists intersect, deny and ask lists union, limits take the minimum,
`record` takes the more verbose. seccomp permits one `NEW_LISTENER` filter per filter chain (verified, `EBUSY`), so
a nested run cannot install its own ask filter: the child's asks are routed through the parent's supervisor (or
`tegod`), which sees the nested run's notifications because the filter is inherited. (*Amended 2026-10-05, ADR 0042
(7)(d)(vi):* through the parent's supervisor only; tegod routes no asks. *Amended 2026-10-06:* designed, not
built. A nested run is refused at start with exit 125 before its agent runs, and the outer run goes on: supervisor
R20.)

**CPU, memory, pids.** cgroup v2 controllers exposed in the contract's `limits` (`cpu`, `cpu_weight`, `memory`,
`memory_high`, `pids`) plus the agent-level budgets (`tokens`, `cost_usd`, `wall`, `stall_after`). An OOM kill or a
pids cap ends the run with `run_end reason=oom|pids`. Machine-wide ceilings and defaults are the machine config
(spec/config/v0): a contract may lower a ceiling, never raise it, and `compile` shows every effective value with its
source.

## 4. Boundaries: daemons, clusters, other hosts

Work handed to a pre-existing daemon starts outside the run's process lineage. What covers it, and in which tier:

1. **Run membership is a set of cgroups.** In the root tiers the BPF maps are keyed by cgroup id, so a run can own
   several cgroups, and a parent entry with a `descendants` flag covers every cgroup created beneath it. Descendants
   are materialized, never walked per hook: a `raw_tracepoint/cgroup_mkdir` program, attached once per host, inserts a
   new cgroup with its parent's run before any task can join it (the tracepoint fires inside `cgroup_mkdir()` before
   `kernfs_activate()`, verified); `cgroup_rmdir` removes it; at adopt time userspace scans cgroupfs for descendants
   that already exist. Every hook stays one lookup on `bpf_get_current_cgroup_id()`.
   In the unprivileged tier there is no adoption: Landlock and the seccomp filter are properties of the launcher's
   process tree, which a daemon-spawned container is not. There, a container created through the proxy (below) is
   enforce-none, record-by-API: every create/start/exec/build request is a `boundary` event, the dangerous fields are
   refused, and the run gets `gap what=enforce` and `gap what=record` for the container.
2. **A per-run Docker API proxy; no PATH shims** (the only PATH shim in the product is E70's `tego-priv`).
   When the contract has a `docker:` section, `tego run` listens on `$XDG_RUNTIME_DIR/tego/<run>/docker.sock`,
   sets `DOCKER_HOST` to it and unsets `DOCKER_CONTEXT`, and resolves the real daemon as the Docker CLI does
   (`DOCKER_HOST`, then `DOCKER_CONTEXT`, then `currentContext` in the config file, then the default socket; verified
   in docker/cli). CLI, compose, docker-py and the Go client all take `DOCKER_HOST` first. Only `--context`/`-H` flags
   and hard-coded clients bypass it, and they hit the real socket, which stays `ask`. See §9 for what the proxy does.
3. **Identity propagation** (normative table in `spec/identity/RUN-IDENTITY.md`): `TEGO_RUN_ID`,
   `TEGO_PARENT_RUN`; `OTEL_RESOURCE_ATTRIBUTES` with `tego.run=<id>,tego.agent=<name>` appended (SDKs merge it as
   the secondary resource, verified); `PGAPPNAME=tego:<id>` only when unset (honoured by libpq, pgx, node-postgres;
   a DSN `application_name` wins; asyncpg ignores it; 63 bytes in `pg_stat_activity`, full value in `log_line_prefix
   %a`, which pgaudit lines use; verified). Through the forwarder: `X-Tego-Run`, W3C `traceparent` (a run-derived
   trace id when the client sent none, else the client's, with a fresh parent id) and `tracestate` member
   `tego=<id>`. The run id never goes inside `traceparent` (fixed hex fields, verified against the W3C spec).
4. **Env-propagation linking.** Any process in any tego-managed cgroup whose initial environment carries
   `TEGO_PARENT_RUN` is linked to that run. Nothing puts it there by itself; each system has its own carrier:
   Ray via `RAY_RUNTIME_ENV_HOOK` and a shipped adapter that `setdefault`s the id into `runtime_env.env_vars`
   (verified mechanism; jobs submitted with the Python job client have no hook and are boundary-only); Celery carries
   headers, not environment, so it is boundary-only by default (opt-in adapter later); Kubernetes pod env comes from
   the PodSpec, so pods are boundary-only.
5. **Shared runs for clusters.** Cluster daemons run under their own contract (`tego run -- ray start --head`), so
   worker actions are recorded in the cluster's run and linked to submitting runs by (4) where a carrier exists.
6. **Rootless podman, bubblewrap, `unshare -m`, and agent-started sandboxes** are not free: with fs rights in the
   Landlock domain the kernel refuses `mount(2)`, `move_mount`, `umount`, `remount` and `pivot_root` for every
   sandboxed thread (verified in `security/landlock/fs.c` and by `bwrap` under a domain on the test machine), and setuid
   `newuidmap` is neutered by `no_new_privs`. In the unprivileged tier they are refused and recorded as
   `gap what=enforce why=landlock-topology`; `compile` warns when `exec.allow` names podman, buildah or bwrap. In the
   root tiers a contract may declare `containers: rootless`, which omits filesystem rights from the Landlock ruleset
   (network and scope rights stay) and relies on the BPF path rules; podman's scopes are adopted by lineage (a seccomp
   notification from a pid whose cgroup is not yet in the run set adds it), and identity reaches the container through
   `CONTAINERS_CONF_OVERRIDE` env and annotations with `{append=true}`.

What remains uncovered: effects inside systems that never run under Tego anywhere. Boundary events plus propagated
identity are the maximum. Every runtime shares this limit.

**Distribution across machines.** Kernel enforcement is per host, so a distributed agent is many single-host runs
sharing the standards: globally unique run ids with the host id inside, ledgers that merge by concatenation with the
hash chain proving completeness, a portable contract, `TEGO_PARENT_RUN` carried by Ray's `runtime_env`, a Celery
header (opt-in), and asks routed by id. There is no cross-host view. (*Amended 2026-10-05, ADR 0042 (7)(h):* tegod, which
is not built, would be a per-run root broker, with no host-wide ring reader or ledger writer.)

## 5. The child stage (verified facts, ADR 0006 as amended)

Go cannot run code between fork and exec, so `tego run` re-execs itself:

```
tego run  (parent)
  ├─ prctl(PR_SET_CHILD_SUBREAPER, 1)         so daemonized descendants stay Yama-scope-1 descendants
  ├─ create the run cgroup; open the ledger; take runs/<id>/lock (flock)
  ├─ clone3(CLONE_PIDFD | CLONE_INTO_CGROUP) → tego __child --run <id>   (control pipe inherited)
  │      child, on one locked OS thread, execs /proc/self/exe never argv[0]:
  │        1. set env (identity, propagation set, env.set, forwarder base URL, NO_PROXY), cwd
  │        2. drop to the invoking uid/gid if the parent was privileged, that gid its only supplementary group
  │           (their other groups are not carried, runtime-launch.md R4a); drop every capability (capset to empty,
  │           PR_CAP_AMBIENT_CLEAR_ALL); prctl(PR_SET_DUMPABLE, 1)  — a stage re-exec'd from a file-capability
  │           binary or dropped from root is non-dumpable, and pidfd_getfd refuses non-dumpable targets (verified;
  │           a file-capability binary is refused before the stage since ADR 0042 (3)(a), 2026-10-05)
  │        3. prctl(PR_SET_PDEATHSIG, SIGKILL)  after the last credential change (commit_creds clears it)
  │        4. prctl(PR_SET_NO_NEW_PRIVS, 1)     (on ABI 11+ folded into step 5 as LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS,
  │           which sets it only if the call succeeds and requires a ruleset; observe mode keeps the prctl)
  │        5. landlock_restrict_self(ruleset)   restricts this thread; execve carries it forward
  │        6. seccomp(SET_MODE_FILTER, NEW_LISTENER) → notify fd
  │        7. write the notify fd NUMBER to the control pipe (write(2) is never trapped)
  │        8. wait for the parent's ack; execve(agent command)
  └─ parent: pidfd_getfd(child_pidfd, notify_fd)  (5.6+, Go SysProcAttr.PidFD; runc's procSeccomp protocol),
             start NOTIF_RECV before acking (the child's own execve is the first notification),
             then supervisor goroutines: notify fd, ring buffer, forwarder, limits; wait on cgroup.events
```

Why this shape: seccomp filters and Landlock domains survive `execve` (verified); `NEW_LISTENER` cannot be combined
with `TSYNC` (verified, `EINVAL` unless `TSYNC_ESRCH`), so one thread that execs immediately is right; passing the
notify fd with `SCM_RIGHTS` would be trapped by the filter's own `sendmsg` rule, so the parent pulls it with
`pidfd_getfd` instead (the alternative is to bake the control fd into the filter as an exemption). `privileged: true`
(root launcher only) changes the order: steps 5 and 6 run before step 2 while the thread still holds `CAP_SYS_ADMIN`,
and step 4 runs last, after the drop (ADR 0033; skipped only under a contract's `setuid: true`). Without `no_new_privs` and without `CAP_SYS_ADMIN`, `landlock_restrict_self` fails with `EPERM`
and `seccomp(SET_MODE_FILTER)` with `EACCES`, and a `setresuid` from root clears the permitted, effective and ambient
sets (verified on the test machine and in `commoncap.c`). The domain lives in the cred and is copied on `setresuid`; the filter
lives on the task; both survive `execve`, so setuid binaries work inside the run and remain Landlocked and asked (their
processes are non-dumpable, so only a root supervisor can serve their asks).

## 6. Lifecycle: signals, supervisor death, orphans, pins, upgrades

- **Signals.** The agent shares the launcher's process group, so terminal-generated `SIGINT`/`SIGQUIT`/`SIGTSTP`/
  `SIGWINCH` reach it directly and are not re-sent (kernel-generated signals bypass Landlock signal scoping,
  verified). `tego run` forwards `SIGTERM`/`SIGHUP`/`SIGUSR1`/`SIGUSR2` always, `SIGINT`/`SIGQUIT` only when stdin is
  not a terminal. `SIGINT`/`SIGTERM`/`SIGHUP` start `stop_grace` (default 10 s); a second `SIGINT` within 2 s or expiry
  writes `cgroup.kill`. `run_end reason=signal signal=<n> escalated=<bool>`; the exit code stays the agent's own.
  A `SIGHUP` the launcher inherited as ignored (`nohup`) stays ignored, for it and the agent. An agent that stops
  itself stops the launcher with it when they share a terminal, and is resumed when the launcher is continued
  (runtime-launch.md R9b).
- **Supervisor death.** `PDEATHSIG` kills the agent's main process; descendants keep the inherited filter and, with
  the listener closed, every notified syscall fails with `ENOSYS` (verified) while Landlock and cgroup limits persist:
  the intended fail-closed state, stated in the README, collected by the sweep. At tier 2 the run's cgroup links are
  pinned under `<bpf_hash>/links/run-<id>/`, so the network programs persist too, and the run's reaper (ADR 0020,
  built 2026-09-29), `tego __reap`, which the launcher starts after `Prepare` in `tego.slice/helpers.scope` with a
  pidfd it opened on itself and the run directory's descriptor, wakes when the launcher dies, kills the cgroup,
  writes `run_end reason=orphaned`, removes the cgroup and only then unpins the links and purges the run's rows; a
  reaper that cannot start refuses the run in the fanotify fallback. A run with a DNS broker endpoint gets a reaper at
  every tier, which also removes that endpoint once the tree is gone, and does not start without one (ADR 0020's
  2026-10-05 note). Under `tegod` the daemon owns the lifetime.
  (*Amended 2026-10-05, ADR 0042 (7)(b):* there is no resident daemon; under tegod, when a trigger builds it, each
  run's per-connection instance starts ADR 0020's reaper exactly as a sudo launcher does.)
- **Liveness and the orphan sweep.** The supervisor holds `runs/<id>/lock` with `flock(LOCK_EX)`; the kernel
  releases it when the holder dies, so "live" is "lock held", with no pid reuse and no state file. `tego run`, `stop`
  and `gc` sweep: for a run with `run_start` and no `run_end` whose lock is free, take the lock, `cgroup.kill` if
  populated, append `run_end reason=orphaned` (the one line written by a process other than the launcher: the run's
  reaper or a sweep), remove the cgroup and the run's sockets and, as root, the run's pinned links and rows under the
  build its `run_start.bpf_hash` names. `tego status` never writes; it shows `lost`.
- **Pins.** Programs, maps and links are pinned under `/sys/fs/bpf/tego/<bpf_hash>/`, `bpf_hash` being the first 16
  hex of SHA-256 over the named embedded BPF object bytes in a fixed order. Binaries with the same objects share maps;
  changed objects use a different pin directory (cilium/ebpf's compatibility check sees sizes, not struct layout).
  bpffs cannot hold regular files, so the build lock is `/run/tego/bpf-<bpf_hash>.lock` (the non-root `tegod`
  directory once named here is dropped: tegod is root, ADR 0042 (7)): every launcher of that build holds it
  `LOCK_SH`; on exit a launcher tries `LOCK_EX|LOCK_NB` and, on success, unpins and detaches. Two builds coexist
  during an upgrade; every hook then runs both programs (`fmod_ret` programs run in sequence, first non-zero return
  wins), each returning 0 for cgroups not in its own maps. The capture programs are pinned beside the build's own, and
  the capture probes are the build's, one directory of pinned links per library,
  `<bpf_hash>/uprobes/<dev>-<ino>-<build id>/`, held `LOCK_SH` by every run using the library through
  `/run/tego/bpf-<bpf_hash>-lib-<...>.lock`; the last run out hands them to `tego __uprobe-detach`, which removes
  them 2 s later unless a run holds them again (ADR 0026 (7), (9) as amended 2026-09-24). `tego doctor` lists every
  build with what it holds; `tego gc --builds` removes idle ones now.
- **Host state (ADR 0034, 2026-09-24).** The build locks and slot tables every launcher of a build shares live in
  `/run/tego` and nowhere else: root 0700 (a root launcher creates it so), opened `O_PATH|O_NOFOLLOW` and
  verified, every file in it opened relative to that descriptor and refused unless the launcher's effective uid owns
  it (`internal/runtime/hoststate`). The per-user fallbacks are gone: they split one build's locks and slots between
  users. (*Amended 2026-10-05, ADR 0042 (3)(b):* the root:tego 1770 form for a file-capability install and its
  tmpfiles line are withdrawn; no launcher used them, and they gave root's slot tables and locks to the group.)
- **Binary upgrade.** Installs replace by rename; a live `tego run` keeps its inode and the child stage execs
  `/proc/self/exe`, so a run is always one build. `run_start` records `tego_version` and `bpf_hash`. Versioning and
  ledger compatibility rules are in `docs/VERSIONING.md`.

## 7. Ask without races (ADR 0008 as amended)

- Approved **opens**: the supervisor, on a dedicated locked thread that first adopts the target's identity
  (`setfsuid`/`setfsgid`/`setgroups` and umask from `/proc/<pid>/status`, `dirfd` and relative paths resolved through
  `/proc/<pid>/fd/<n>` or `/proc/<pid>/cwd` under `/proc/<pid>/root` with `openat2(RESOLVE_IN_ROOT)`, the target's
  flags and mode verbatim), opens the verified path and injects the fd with `SECCOMP_IOCTL_NOTIF_ADDFD` +
  `SECCOMP_ADDFD_FLAG_SEND` (atomic, 5.14+, verified). A root launcher never opens with root credentials. The
  injected fd is usable by the target even though it was opened outside the domain (Landlock does not restrict
  already-open fds, verified).
- Approved **connects**: the supervisor takes a duplicate of the target's socket with `pidfd_getfd` (5.6+, same open
  file description, verified) and performs the `connect()` itself with the sockaddr it read; it returns the real
  result (0 or `-EINPROGRESS` for non-blocking sockets). Undeclared hosts get `-EACCES` with a reason, the errno of
  a connect the supervisor refuses, in every tier (SEMANTICS §5); `ECONNREFUSED` stays what a real peer answers, which a relay returns as it
  came. (*Amended 2026-09-23:* this said `-ECONNREFUSED`, which the supervisor never returned; and then "the errno of a
  network refusal in every tier", which SEMANTICS §5 does not say: at tier 2 an unconnected datagram the supervisor
  continues meets the kernel program's `-EPERM`, and Landlock's abstract-unix scope refuses with `-EPERM`. It then
  said "the errno of a refused connect in every tier", which those same two contradict for a connect the kernel
  refuses rather than the supervisor, a relayed one the tier-2 rows refuse and an abstract-unix one Landlock's
  scope refuses.)
  **This makes host-level deny an unprivileged-tier property**: Landlock handles `CONNECT_TCP` and each declared port
  becomes a rule, which sees the port and never the host, so a `connect(2)` that reaches the kernel from inside the run
  to an undeclared port is refused with `EACCES`; every
  allowed connect is performed by the supervisor on the duplicate (Landlock evaluates the calling task's domain, and
  the supervisor is unrestricted), so `CONTINUE` is never used for a connect decision. A `sendto`/`sendmsg` with an
  address on a stream socket (TCP Fast Open) is decided exactly like a connect. A relative `sun_path` is resolved
  against `/proc/<pid>/cwd`. Nested runs compose by construction: a nested supervisor's own connects are intercepted
  by the parent's filter. UDP datagram sends in this tier remain best-effort (address read: a refused destination is
  refused with `-EACCES`, an admitted one `CONTINUE`d and read again by the kernel; a stated TOCTOU limit on the allow
  only, amended 2026-10-16, supervisor R13b); race-free UDP is a root-tier property (`socket_sendmsg`, `cgroup/sendmsg`).
- `ask` entries carry no rights of their own in any tier: they compile as refused, and the approval is the
  supervisor's `ADDFD` or connect-on-duplicate, never a `CONTINUE`. Other modifications inside an `fs.ask` directory
  (rename, unlink, mkdir, truncate, chmod) are refused, not asked.
- Every read of target memory is bracketed by `SECCOMP_IOCTL_NOTIF_ID_VALID` (verified requirement).
- **The filter.** Before matching any syscall number it verifies `seccomp_data.arch == AUDIT_ARCH_X86_64` (or the
  build's native arch) and that the x32 bit is clear in `nr`; a call from another ABI is refused with `-ENOSYS`, because
  compat ABIs renumber `open`/`openat`/`connect`. Returns `-ENOSYS` for `io_uring_setup/enter/register` (as Docker's default profile does), because
  io_uring submits opens, connects and sends with no syscall the supervisor could see; a contract may lift this with
  `io_uring: true` in the root tiers only, where the LSM hooks see the operations. Notifies on `open`, `openat`,
  `creat` when `flags & (O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)` (`BPF_JSET`, mask `0x243`; `O_TMPFILE` implies write);
  returns `-ENOSYS` for `openat2` so callers fall back to `openat` (its flags live in target memory). Notifies on
  `connect` (where a connected datagram socket is decided; glibc's resolver connects before sending, verified),
  `sendto` only when the address argument is non-NULL, `sendmsg`/`sendmmsg` on known datagram fds when `msg_name` is
  set, `execve`/`execveat`, and in the unprivileged tier `unlink*`/`rename*`/`mkdir*`/`symlink*`; in a run that decides
  datagrams also a `sendto` with no address carrying `MSG_MORE`, `setsockopt(UDP_CORK)`, `sendfile` and `splice`, so
  no UDP frame is left pending (enforce-landlock R11d, amended 2026-10-20). Read-opens never leave the kernel.
- **Yama.** The parent supervisor satisfies `PTRACE_MODE_ATTACH_REALCREDS` over descendants of the same uid under
  `ptrace_scope=1`; the subreaper flag keeps daemonized descendants in that set. A non-dumpable target (its own
  `PR_SET_DUMPABLE=0`, or a setuid exec under `privileged: true`) can be served only by a supervisor with
  `CAP_SYS_PTRACE`; an unprivileged supervisor refuses its asks with `ask-unreadable` and records a gap. `tegod` holds
  `CAP_SYS_PTRACE`; Yama scope 3 disables asks and `doctor` says so. (*Amended 2026-10-05, ADR 0042 (7)(d)(iii):*
  tegod reads no agent memory; it holds `CAP_SYS_PTRACE` only to read a peer's or a run member's namespaces and
  `map_files`, and asks stay the client's supervisor's.)
- **Client timeouts.** `ask.hold: request` holds an HTTP request inside the forwarder. Ceilings are the client's:
  Claude Code waits 600 s for headers and retries up to 10 times, the Python SDK 600 s and 2 retries, Codex 300 s idle
  and 4 to 5 retries. A retry of a held request (same method, path, body hash and credential; `x-stainless-retry-count`
  when present) attaches to the pending ask and is answered with it; `ask.timeout` for `request` defaults to 4 minutes
  so a deny reaches the client as a `403` with reason before the client's own timeout.

## 8. The record in each tier

**Root tiers.** eBPF tracepoints and kprobes for exec, exit, open, unlink, rename, connect; a process cache; a ring
buffer per run (one buffer shared by all CPUs, at the run's slot in a ring outer, size from `/etc/tego/config.yaml`,
drained only by the run's own launcher; ADR 0026); in-kernel filtering by cgroup so only managed cgroups reach
userspace. Reads are aggregated per (exec id, nearest rule) except `deny_read` and `fs.watch` paths,
which are always individual events.

**Unprivileged tier.** The seccomp supervisor is the recorder: exec with argv, write-opens, connects, datagram
sends, deletes and renames from the notifications above; exits from `cgroup.events`; model traffic from the forwarder.
This record is read-before-continue and therefore advisory against a hostile process (the man page's TOCTOU); the
capability matrix says so per run. Reads are not recorded in this tier unless `record: full`, which notifies on every
open and is slow by design.

**Attribution.** Every action event carries `attribution{thread, step, tool_use_id, confidence:
exact|likely|unattributed, method: tool_id|tid|time|none}`. `none` means no derivation has run (M1 ledgers); `tool_id`
ties the action to the reply whose tool window it fell in (the reply asked for the `tool_use` and no request had yet
reported its result) and names it in `tool_use_id`; `tid` ties it to the step of the thread that made it, where the
uprobe source names threads by tid; `time` is the step-by-time rule, the fallback (capture-derive R42, R34).
Every attributed action is `likely`; `exact` is never written. Views never present `unattributed` as fact.

## 9. Docker and daemons: the API proxy

On the first request of a run the proxy reads `GET /info` (`CgroupDriver`, `CgroupVersion`, `SecurityOptions`,
capability booleans) and caches it. In the root tiers, before the first `create` is forwarded, it pre-creates the
run's container parent in the manager the daemon uses: systemd driver (the default on cgroup-v2 systemd hosts)
`StartTransientUnit tego-<agent>-<runslug>.slice` (system bus for rootful dockerd, user bus for rootless; `runslug`
is the run id with dashes removed, because systemd encodes hierarchy in dashes); cgroupfs driver `mkdir
/sys/fs/cgroup/tego/<agent>/<run>`; driver `none` (rootless without systemd) cannot be adopted and is recorded as a
boundary with a gap. The parent's cgroup id goes into the run set with `descendants`, so the container is covered
from its first instruction (§4.1); the `start` event and `State.Pid` → `/proc/<pid>/cgroup` only write the
container → cgroup line into the ledger, and the proxy holds the `start` response until that line is written. Docker
logs `start` only after the process runs (verified in moby), which is why adoption is by ancestry, not by event.

On `POST /containers/create` the proxy overwrites `HostConfig.CgroupParent` with that parent, sets
`Labels["tego.run"]`, clears `HostConfig.Cgroup`, copies the contract's `limits` into `NanoCpus`, `Memory`,
`PidsLimit`, injects `host.docker.internal:host-gateway` and the forwarder base-URL variables into `Env` when capture
is on, and, unless the contract's `docker.allow`/`docker.ask` names the item, refuses: `Privileged`; `CapAdd`;
`Devices`; `DeviceCgroupRules`; any `SecurityOpt` other than `no-new-privileges` and `label=`; a present `MaskedPaths`
or `ReadonlyPaths`; `PidMode`, `IpcMode`, `NetworkMode`, `UsernsMode`, `CgroupnsMode` equal to `host` or to a
container the run does not own; `VolumesFrom` of a foreign container; any bind or `Mounts` entry whose host source,
after realpath, is the Docker socket, `/`, `/proc`, `/sys`, `/dev`, `/var/lib/docker`, `~/.docker`, or, for `rw`, is
outside `fs.write`, or, for `ro`, is under `deny_read` or unreadable by the invoking uid; volume `DriverConfig.Options`
(the `local` driver mounts any device). `POST /volumes/create` refuses `DriverOpts`. Every route with a container id
is resolved through `GET /containers/{id}/json`, the container must carry the run's label (or an ancestor run's), and
the request is forwarded with the resolved 64-hex id, which closes the rename window. `exec` refuses
`ExecConfig.Privileged` (moby gives it the full capability set, verified). Swarm, services, nodes, secrets, configs
and plugin write routes are refused unless declared. `/build` is forwarded and recorded as a boundary (context bytes,
Dockerfile hash, tags); `networkmode=host` and `securityopt` on `/build` are refused unless declared; BuildKit RUN
steps run under the daemon's builder cgroup and are a stated gap. Every refusal is a `refused` event with
`rule: docker.<name>` and a 403 whose JSON `message` carries the reason. At `start`, the proxy reads
`GraphDriver.Data.MergedDir` and adds that inode with the access set of `containers.rootfs` (default `write`), because
an overlay rootfs has no host ancestor (§10). Inside adopted containers `ask` is `refused` with `ask-unavailable`
(the filter is a property of the launcher's tree), and capture needs uprobes attached to the
container's own libssl through `/proc/<pid>/root` or the injected forwarder variables.

## 10. Filesystem rules: inode identity and the ancestry walk (ADR 0005, ADR 0010)

*Note 2026-09-29 (ADR 0025 supersedes ADR 0010's storage, accepted; built at T2 to T6, run at tier 2; [enforce-plane](p0/enforce-plane.md) R5, R6, R7, R16):* the `BPF_MAP_TYPE_INODE_STORAGE` object ids and the `{cgroup id, object id}` hash below are superseded by per-run inner row maps keyed by the kernel `struct inode *`, filled in the kernel from the held O_PATH descriptors and pinned by the run's own Landlock domain (one neutral rule per keyed inode), so no inode-storage map is ever created and GAPS B6 leaves the design. The walk paragraph (mount crossing, 64 steps, `path-unresolved`, REFER) stands and is now the plane's walk (R7). The text below is kept as the design history: no inode-storage map exists in the tree.

- **Identity is the kernel inode object, never a `stat()` pair.** On btrfs `st_dev` is a per-subvolume anonymous
  number and inode numbers repeat across subvolumes; on overlayfs a non-directory's numbers can come from either layer
  (verified). At run start the launcher opens every declared path `O_PATH` and holds the fd until `run_end`, which pins
  the inode; it assigns the inode an object id in a host-wide `BPF_MAP_TYPE_INODE_STORAGE` map keyed by that fd
  (`BPF_NOEXIST`, re-read on `EEXIST`), and the run's access sets live in a hash map keyed `{cgroup id, object id}`.
  Landlock rules are added from the same fds. `compile` never computes an inode; it only checks that paths exist.
  The inode-storage map is created only in tier 3 and only after `doctor` has confirmed `bpf` is an active LSM,
  in this order: `lsm_list_modules(2)` (6.8+, unprivileged, `LSM_ID_BPF`), then `/sys/kernel/security/lsm`, then the
  kernel log; and a functional probe when root (attach a counting program to `file_open`, open a file, require a
  count, no inode-storage map in the probe). Activation is silent: an LSM program attaches even when `bpf` is not
  active and then never runs (verified: `bpf_lsm_verify_prog` checks licence and hook membership only). On every
  kernel below 7.1.4 / 7.2-rc2, including 6.17, creating an inode-storage map while BPF LSM is inactive succeeds and
  the first element update corrupts `inode->i_security` (verified in `bpf_inode_storage.c`); newer kernels return
  `EOPNOTSUPP`. The printed fix is the active list plus `,bpf`.
- **The walk is on `(mount, dentry)` pairs and crosses mounts**, the same walk `d_path`, Landlock's `follow_up` and
  Tetragon perform: look the dentry's inode up; if it is the mount root, continue at the mountpoint dentry in the
  parent mount unless this is the global root; if it is a disconnected root, stop (`path-unresolved`, refused); else
  go to `d_parent`. Bounded to 64 steps, a mount crossing counting none. Starting points: `path_*` hooks use
  `(dir->mnt, dentry)` (both sides for rename and link), `file_open` and `bprm_check_security` use the file's path,
  the unix hooks use the bound socket's path. The `inode_*` hooks carry no mount and are not used.
- **Consequences.** A rule on `/work` covers a tmpfs mounted at `/work/.cache`. Bind mounts share dentries and inodes
  with their source, so a rule on the source directory applies through the bind, including a container volume,
  without translation; a rule on an ancestor of the source does not. An overlay rootfs has its own superblock: rules
  on upper or lower directories do not apply to the merged tree (Landlock documents the same), which is why §9 adds
  the merged root explicitly. Hard links and renames cannot move a file out of a rule, but can create a name under a
  less restricted directory, so `path_link` and `path_rename` refuse when the source's nearest entry is more
  restrictive than the destination's (Landlock's `REFER` rule), so both tiers behave the same. `compile` prints each
  entry's mount, filesystem and device, and warns on mount points, overlay layers and btrfs.
- **Why not strings.** From a BPF LSM program `bpf_d_path` is allowed only when the hook is in the kernel's
  sleepable set (`bpf_d_path_allowed`, verified; the `btf_allowlist_d_path` list next to it governs fentry programs);
  `bprm_check_security`, `file_open`, `bpf` and the `socket_*` hooks have been in that set since 5.11, but the `path_*`
  hooks joined it only in 6.8 and the `bpf_path_d_path` kfunc exists from 6.12, so string rules would not run on
  6.1–6.7; the sleepable `inode_*` hooks provide no `struct path`; and a string prefix does not follow a rename, a
  hard link or a bind mount. Ancestry works in every hook on every supported kernel.

## 11. The hardened hook set (tier 3) and its portability rules

*Note 2026-09-29 (ADR 0024, accepted; steps A to D built as of 2026-09-30, T13 to T15; [enforce-plane](p0/enforce-plane.md) R3, R4, R14, R26):* the hook set is built as one CO-RE object with each body exposed as `lsm/<hook>` and `fmod_ret/security_<hook>`, in landing steps A to D: `file_open`, `bprm_check_security`, `path_*`, `inode_*` protection hooks, `socket_create`, `mmap_file`/`file_mprotect`, and the unix hooks below 6.7. `socket_connect`, `socket_bind`, `socket_sendmsg`, `ptrace_*`, `bpf` and `key_permission` remain FEATURES E54 (P1), and network stays on the per-run cgroup programs. Built (`bpf/decide.bpf.c`, `decide_stepb.h`, `decide_stepc.h`): step A `file_open`, `bprm_check_security`, `path_rename`, `path_link`, `path_unlink`, `path_rmdir`; step B `path_mknod`, `path_mkdir`, `path_symlink`, `path_truncate`, `file_truncate`, `path_chmod`, `path_chown`, the `inode_*` xattr/ACL protection hooks and `socket_create` (T13); step C `mmap_file`/`file_mprotect` (T14); the unix hooks (T15). Remaining per TIER3-PLAN: T9b, T11, T16. The rule that `inode_*` hooks are not used is replaced for `deny_write` protection only (R12, built, T13).

*Current selected implementation, 2026-10-05:* the above note describes its dated A–D checkpoint. The selected extension now includes actual Unix `socket_bind`/`socket_listen` admission and the scoped ptrace, BPF-command and key-permission controls (`bpf/decide_socket.h`, `decide_listen.h`, `decide_control.h`). Ptrace attachment and traceme require the same run/generation; read-mode ptrace checks remain with the ordinary LSM chain. Ordinary INET network decisions use the cgroup/supervisor mechanisms documented in [network controls](p0/network-controls.md). Each capability requires its actual probe/load/attachment proof; these changes do not close the remaining engineering checklist or unmeasured platforms.

`file_open` (treats `O_TRUNC` as a write), `path_unlink`, `path_rename`, `path_mkdir`, `path_rmdir`, `path_symlink`,
`path_link`, `path_mknod` (mkfifo, mknod, and the inode a unix `bind()` creates), `path_truncate` always plus
`file_truncate` where the kernel has it (6.2+: `ftruncate` and `O_TRUNC` moved there), `path_chmod`, `path_chown`,
`bprm_check_security` (once per binfmt stage: a `#!` stage passes and the interpreter or native binary decides,
`spec/policy/SEMANTICS.md` §4; verified in `fs/exec.c`), `socket_connect` (decides inet TCP and UDP connects on the
kernel copy of the address; for AF_UNIX it only records `sun_path` because the name is unresolved there),
`socket_bind`, `socket_sendmsg` (fires on every send on every socket; returns 0 immediately unless the socket is inet
datagram or raw; destination from `msg_name` or, when NULL, the connected peer),
`unix_stream_connect` (stream and seqpacket, resolved path; matched on parent-directory inode plus final component so
daemon restarts and the `/var/run → /run` symlink keep matching; abstract names by bytes), `unix_may_send` (datagram,
same rule), `ptrace_access_check` and `ptrace_traceme` (run-tree scoped, both modes: a task in a run may inspect or attach only
to a task whose run is its own or a nested child, looked up from the target's cgroup in the run set, never by cgroup
equality; this mirrors the scoping every Landlock domain already imposes in every tier, verified in
`security/landlock/task.c`. `ps`, `top`, `pgrep` and `psutil.process_iter()` keep working because `/proc/<pid>/{stat,
status,cmdline}` need no ptrace access; `exe`, `cwd`, `environ`, `maps`, `mem` and `pidfd_getfd` on a pid outside the
run are refused),
`bpf` (no `bpf(2)` inside a run). All 20 exist as `bpf_lsm_*` attach points on this kernel (verified).

One embedded CO-RE object must load and behave the same from 6.1 onward (verified rules):
1. Declare the 6.1 prototype for every hook and read nothing past it (`bpf` gained a fourth argument in 6.15; reading
   it on older kernels silently reads the return-value slot, not a load error).
2. Return 0 or `-errno`, never a positive value; from 6.12 the verifier bounds LSM returns.
3. `path_truncate` always; `file_truncate` as an optional program attached when its stub is in the kernel BTF.
4. `path_*` need `CONFIG_SECURITY_PATH`, `socket_*`/`unix_*` need `CONFIG_SECURITY_NETWORK`; presence of
   `bpf_lsm_<hook>` in `/sys/kernel/btf/vmlinux` is exactly hook availability, and `doctor` resolves every hook (name
   and argument count) before promising the tier.

Sleepable: `socket_connect`, `socket_bind`, `socket_sendmsg`; not sleepable: the unix hooks and all `path_*` hooks.

## 12. Model-traffic capture and the forwarder

- **Uprobes** (verified): writes hook `SSL_write` and `SSL_write_ex2` when it exists (OpenSSL 3.3+; `SSL_write_ex`
  tail-calls it), else `SSL_write_ex`, never both; reads need an entry+return pair on `SSL_read` (length = return) and
  `SSL_read_ex` (length = `*readbytes` when the return is 1). CPython 3.10+ uses only the `_ex` calls; Node, libcurl
  and CPython 3.9 use the plain ones. Statically linked binaries that keep symbols get the same programs at a
  different path: uv/python-build-standalone Pythons (local symbols in `.symtab`, verified) and official Node
  (exported). Claude Code (Bun, BoringSSL, no symbols) and Codex (rustls) have none. Reassembly is HTTP/1.1 with
  `gzip`, `deflate`, `br` and `zstd` decoding (Cloudflare serves `br` to any client that offers it; httpx2 on Python
  3.14 offers `zstd`); an h2 connection, known by its preface, is recorded as `gap what=capture why=h2` (the
  negotiated ALPN is not read; capture-derive R17, amended 2026-09-24).
- **The forwarder**: one loopback listener per declared model endpoint (`models[]`: provider, host, port), each bound
  to one upstream; it rewrites only `Host`/SNI, forwards every other header and the body byte-for-byte, never buffers a
  response body, passes `retry-after`, `x-should-retry` and rate-limit headers through, and answers `HEAD /api/hello`
  itself. Per harness the run sets: Claude Code and both Agent SDKs `ANTHROPIC_BASE_URL` plus
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` (the fast-mode check and the WebFetch domain check still go direct and
  are refused by `net.allow`; the adapter tags those refusals `expected`); the Python and TypeScript SDKs the same
  variable; Codex a generated `config.toml` under `CODEX_HOME` with `openai_base_url` (its env variable is
  undocumented) and `chatgpt.com` upstream when logged in that way; Gemini CLI `GOOGLE_GEMINI_BASE_URL`,
  `GOOGLE_VERTEX_BASE_URL`, `CODE_ASSIST_ENDPOINT`. A harness that ignores its variable reaches the upstream directly
  and is refused by `net.allow`, never silent. When any `*_PROXY` variable is passed in, the run appends
  `127.0.0.1,localhost` to `NO_PROXY`. `env.mask` is proposed P2 behavior and is not built: a non-empty value is refused by compilation. No sentinel substitution is currently promised. Credentials supplied in environment variables, credential files or `apiKeyHelper` output remain available to the agent; header redaction in the ledger is a separate control and does not remove secrets from request bodies or argv.
  HTTP/1.1 remains the default downstream protocol. An explicit HTTP/2 proxy policy enables prior-knowledge HTTP/2 on the plaintext loopback listener; HTTP/1.1 Upgrade to h2c is not supported. Upstream protocol negotiation is separate.

## 13. Desktop tier (ADR 0009)

The engine stays Linux-only. **macOS**: a Lima VM (Lima ≥ 2.0, `vmType: vz` on macOS ≥ 13.5, project mounted by
virtiofs, CLI native). The shipped template ([examples/lima/tego.yaml](../examples/lima/tego.yaml)) is Ubuntu 24.04 LTS: its
kernel has Landlock, BTF and cgroup v2, so tier 1 needs no setup. Ubuntu does not list `bpf` in the boot LSM list, so
tier 3 needs one GRUB edit and a restart, which the template does not make (doctor prints the line). Lima's own Fedora
template already lists `bpf` and needs no edit. `compile` and inode resolution run inside the VM against the
virtiofs mount, never on the macOS side, and `doctor` runs a mount-identity check (stat two directories, drop caches,
stat again; refuse enforcement on that mount if the numbers changed or two directories share an inode), because
virtiofs on Apple's framework has undocumented inode semantics. **Windows**: WSL2 on Microsoft's kernel, which
ships `CONFIG_BPF_LSM=y`, Landlock, BTF and cgroup v2. Before 6.18.54.1 (WSL 3.0.3, 2026-10-09) its LSM list has no
`bpf`: the hardened tier needs `wsl --update`, or one line in `.wslconfig` (`kernelCommandLine = lsm=<current list>,bpf`)
and `wsl --shutdown`, no custom kernel. From 6.18.54.1 the kernel configuration (`CONFIG_LSM`) ends in `bpf` and the
kernel release notes say "Bpf LSM is enabled by default"; this is read from the configuration, not measured with `tego
doctor`. The unprivileged tier needs nothing; eBPF inside WSL still needs root.

## 14. Support matrix (verified 2026-09-21; the runtime probes, never trusts a version)

*Note 2026-09-29 (ADR 0024, accepted; probe and step A built, the MATRIX suites not: T11; [enforce-plane](p0/enforce-plane.md) R28):* a per-row plane mode column (`tego doctor` D7 has the per-hook rows; the fill, load and probe ran on 6.17, RHEL 9.8's 5.14 and AL2023's 6.1): `lsm` where `bpf` is active (Debian 13, RHEL 9/10, AL2023, Fedora), `fmod_ret` on Ubuntu 24.04/25.10 and WSL2 kernels before 6.18.54.1 without a boot change, `fanotify` where neither passes the probe (lockdown=confidentiality below 6.2, unmeasured arm64). The table below is unchanged; the per-mode host-cost table lands with T11's kill tests.

*Note 2026-10-06:* T11's suites are built (TIER3-PLAN §10); the plane mode per row and boot is measured by
`make vm-matrix` as `cgroup_mode` (TIER3-PLAN §7, test/vm/README.md), and the per-mode costs are enforce-plane §2.18
and §10.1.

*Note 2026-10-05 ([test/vm](../test/vm/README.md)):* the matrix gained three rows. Ubuntu 25.10's GA kernel (6.17, ABI 7) is the kernel the project is developed on. Fedora 7.2 is the first row with Landlock ABI 9 and 10, so the pathname unix socket and UDP port rules run against a kernel that has them. Ubuntu 22.04's GA kernel (5.15, ABI 1) is a doctor-only row: it asserts the refusal in the table's first line instead of running the kill tests, since no tier is offered there. Ubuntu 22.04 GA is not a supported platform; the table says what Tego does on it.

Mechanism minimums upstream: `cgroup.kill` 5.14 · Landlock ABI 1 fs 5.13, 2 refer 5.19, 3 truncate 6.2, 4 TCP 6.7,
5 ioctl_dev 6.10, 6 scopes 6.12, 7 audit 6.15, 8 TSYNC 7.0, 9 pathname unix 7.1, 10 UDP 7.2, 11 NO_NEW_PRIVS flag 7.3 ·
BPF LSM 5.7 · ring buffer and CAP_BPF 5.8 · inode local storage and sleepable programs 5.10 · seccomp NEW_LISTENER 5.0,
CONTINUE 5.5, ADDFD 5.9, ADDFD_FLAG_SEND 5.14 · pidfd_getfd 5.6 · cgroup socket programs 4.17/4.18, `connect_unix` 6.7 ·
fanotify exec-perm 5.0, `FAN_DENY_ERRNO` 6.13. **Tested floor: 6.1** (ABI 1 kernels 5.13–5.18 are unsupported: rename and
link confined to one directory).

| Target | Kernel | `bpf` in LSM list | Landlock ABI | Out of the box |
|---|---|---|---|---|
| Ubuntu 22.04 GA | 5.15 | no | 1 | no tier: ABI 1 is unsupported. `tego doctor` says `tier: none` with the fix (boot a kernel >= 5.19) and `tego run` exits 125 `[tier-unavailable]`; test/vm's doctor-only row asserts it |
| Ubuntu 24.04 | 6.8 | no | 4 | tier 1 (fs + TCP port); tier 2 with sudo; tier 3 after the GRUB drop-in + reboot |
| Ubuntu 25.10 / 26.04 | 6.17 / 7.0 | no | 7 / 8 | same, plus scopes and audit |
| Debian 13 | 6.12 | yes | 6 | all tiers, no edit |
| Fedora 40–45 | 6.8–7.2 | yes | 4–10 | all tiers, no edit (7.2 measured 2026-10-05: ABI 10, tier bpflsm on the kernel's own `lsm=`) |
| RHEL 9 / Alma / Rocky 9 | 5.14 + backports | yes | 6 (backported) | all tiers, no edit; full target through ABI 6, missing only post-ABI-6 features (TSYNC, pathname unix, UDP rules), none of which gates a tier |
| RHEL 10 | 6.12 | yes | 6 | all tiers, no edit |
| Amazon Linux 2023 default | 6.1 | yes | 2 | tiers 2 and 3 full; tier 1 fs-only (no net rules); `kernel6.12` gives ABI 6 |
| WSL2, kernel before 6.18.54.1 (WSL 2.9) | 6.18 (6.6 on old installs) | no | 7 (3 on 6.6) | tier 1; tier 3 after `wsl --update` or `.wslconfig kernelCommandLine`; root for eBPF |
| WSL2, kernel 6.18.54.1 and later (WSL 3.0.3) | 6.18 | yes (from the kernel configuration; not measured) | 7 (not measured) | tier 1; tier 3 with no edit once `tego doctor` shows `bpf`; root for eBPF; untested on real hardware |
| macOS Lima, Tego's template (Ubuntu 24.04, cloud image release-20260926) | 6.8 | no | 4 | the Ubuntu 24.04 row: tier 1; tier 2 with sudo; tier 3 after the GRUB edit and a restart (the template does not make it) |
| macOS Lima, Fedora template (Lima's own, not Tego's) | 7.x | yes | 8 | all tiers, no edit |
| macOS Lima, `template:ubuntu` (Lima's own: 26.04 in Lima 2.2.1, not Tego's) | 7.0 | no | 8 | tier 1; tier 3 after the GRUB edit |
| Hosted CI (GitHub ubuntu-24.04) | Ubuntu | no | ≥ 4 | tier 1 + forwarder only; command line not editable |

## 15. Performance and scale

1. **Cost must not scale with the number of agents.** Programs are attached once per host and pinned; a new run adds
   map entries and its own rings. Concurrent launchers share the build lock (§6). The rings are the one cost that
   does scale with concurrent runs: a record ring and, with uprobe capture, a capture ring of `record.ringbuf` each
   (2 MiB default, about 4.2 MB of memlock for both), capped host-wide by `bpf.ring_budget` (256 MiB default, about
   60 such runs); a run past it is refused, or runs without capture (ADR 0026).
2. **Filter in the kernel.** A hook that finds no entry for the current cgroup returns in nanoseconds; only managed
   cgroups and requested kinds cross the ring buffer.
3. **Never block the agent for the record.** Ring buffer drops are counted into a `gap` event; enforcement decisions
   are made in the kernel and never dropped.
4. **Record what is asked.** `record: full | summary | off`; reads aggregated per prefix except watched paths.
5. **Model traffic is cheap to capture.** Each TLS read or write costs two probe hits (entry and return), one to two
   microseconds each; the forwarder adds roughly a hundred microseconds per request. Both vanish next to model latency.
6. **Ask only holds what is asked, and the filter cannot see paths.** Whenever a contract has an `fs.ask` entry the
   filter notifies on every write-open, exec and connect (read-opens never leave the kernel); in the unprivileged tier
   the same filter is always installed for the record. On agent workloads that is a few hundred round trips per run; on
   build-like workloads tens of thousands (an `npm install` of ~350 packages is ~8k write-opens and mkdirs), at 4–8 µs
   each on the test machine, so 30k notifications cost 0.15–0.25 s. Tier 2's fanotify open/exec deny is a userspace round trip
   on every open, reads included, and gets its own benchmark row. (*Amended 2026-10-06, kill test 5, `test/vm/README.md`:*
   the 4–8 µs is the design baseline's estimate (2026-09-22, before any supervisor code existed, with no benchmark cited),
   not an end-to-end measurement; [supervisor](p0/supervisor.md) E17 gives the supervisor's own measured figures.
   Measured end to end in the 2-vCPU KVM guests of seven matrix rows, on a host other jobs' guests shared, the 2,490
   notifications an `fs.ask` entry keeps at tiers cgroup and bpflsm on the pip build cost 160 to 692 ms, 60 to 280 µs each,
   so the ~8k of an `npm install` would cost about 0.5 to 2 s and 30k about 2 to 8 s, not 0.15–0.25 s. The cost is inside
   the allowance for the workloads kill test 5 names, and the follow-up past it is a filter arm that keeps only the write-opens
   whose path can match an ask scope.)
7. **One writer per host at scale.** On servers `tegod` holds the programs, the ring-buffer readers and one ledger
   writer; `tego run` becomes a thin client that hands over its seccomp notify fd. Same binary, same ledger. Without
   `tegod`, each launcher reads its own run's rings, so concurrent runs of one build each get a full record and
   capture (ADR 0026). (*Superseded 2026-10-05 by ADR 0042 (7):* there is no run host. tegod, built only on a
   trigger, is a per-run root instance beside the unprivileged `tego run`, which keeps its supervisor, ring parsing
   and ledger; ring bytes are relayed to it, never ring descriptors. ADRs 0004 and 0026 stand.)

Expected overhead, to be measured by `test/e2e/overhead` (pip install + pytest + npm install,
hyperfine, 10 runs, every tier and record mode): enforce-only under 1%; `summary` plus capture 1 to 3%; `full` 3 to 5%
on builds, near zero on model-bound agents. Targets, not measurements.

## 16. Trusted computing base

`launch`, the child stage, `supervisor`, `enforce/landlock`, `ask` (`internal/runtime/ask`, the approval broker),
`enforce/bpflsm`, `enforce/cgroup` (fanotify listener), `observe`, `capture/uprobe`, `capture/forwarder`, `dnsbroker`,
`mcprelay`, `internal/policy/decide`, the compiled policy they decide with (`pkg/policy/httppolicy`, `dnspolicy`, `gate`,
`fsplan`, `mcptool`), the Docker proxy's policy code when it is built, and the BPF programs with their loader
(`internal/bpf`).
The policy compiler, `pkg/spec/agent`, is not on the list (agent-contract I6). Rules: no third-party dependency beyond cilium/ebpf, go-landlock,
x/sys, x/net; every reader of another process's memory has a Go fuzz target; no external review has been done yet; the
privileged path is `sudo tego run` or a file capability (`cap_bpf,cap_perfmon,cap_sys_admin+ep`) on a copy named by
the root-owned machine config, never a setuid binary.

*Amended 2026-10-05 (ADR 0042 (2), (3)).* The privileged path in this release is a root launcher: `sudo tego run`
on a host whose sudo users are its administrators, or (not built yet) a root launch with `--run-as <user>`.
Granting sudo for tego is granting root: a sudoers entry limited to tego is not a boundary Tego supports, and a
service account never gets one. The file-capability copy is not delivered and fails closed: a launcher that gained
privilege without being root of the initial user namespace (`AT_SECURE`, an id mismatch, or a capability outside
the incidental allowlist) exits 125 `[privileged-path-unsupported]` before anything runs, and one holding only
incidental capabilities has them cleared and runs at tier `landlock`. It may return for single-administrator hosts
only by its own ADR, once ADR 0042 (3)(c)'s conditions hold. Every "uid 0" gate means uid 0 of the initial user
namespace (`config.InitNSRoot`). Users who are not administrators get tier `landlock` until tegod (ADR 0042 (7))
is built on trigger T1.

*Open (2026-09-23), the dependency rule against the module graph.* `go list -deps` over the TCB packages finds
`gopkg.in/yaml.v3` reachable from `launch`, `enforce/cgroup`, `enforce/landlock` and `enforce/observe` (through
`pkg/spec`, whose `agent` and `config` parse YAML), and `andybalholm/brotli` and `klauspost/compress` reachable from
`capture/uprobe`, which imports `capture/httpstream` (ADR 0014 says neither is reachable from the TCB set).
`go-landlock` is on the list but in no shipped package's imports; only `tools/deps.go` pins it. The rule stands as
written; the condition that closes this is either those imports narrowed so the graph matches the list, or the list
and ADR 0014 amended to name what the TCB does depend on and why. Until then `govulncheck` runs on every push and
Dependabot proposes updates for all of them (VERSIONING.md §5). Both reachable decoder modules, brotli and
klauspost/compress, are reached through the one package `httpstream`, and `FuzzFeed` fuzzes that package's input,
decoders included: a fuzzed `Content-Encoding` hands them the fuzzed body (its seeds name gzip only, so `br` and
`zstd` are reached by mutation). The readers of another process's bytes that had no fuzz target now have one:
`FuzzReadBinary` (the ELF files `capture/uprobe` parses as root), `FuzzVerify` and `FuzzBody` (a tampered ledger
and blobs directory) and `FuzzParseRequest` (the agent's request body). Two of them found a defect, each now fixed
with the fuzzer's input committed as a seed under the package's `testdata/fuzz`: `readBinary` bounded a symbol's
file offset by a segment's `Memsz` where only its first `Filesz` bytes come from the file, and it now holds the
offset below `Filesz` and before the file's end, which debug/elf does not check a segment against (capture-derive
R37); and `Reader.Body` read a `blob` body whole with no bound, where it now reads to the event's `size`, held to
1 GiB (record-ledger R11, E16).

*Update 2026-10-19 (ADR 0031 (a)), the Open item above.* `launch` no longer reaches `gopkg.in/yaml.v3`: it
sees the prepared handle through `internal/runtime/enforce/api` and links no backend and neither `pkg/spec/agent` nor
`pkg/spec/config` (`TestLaunchLinksNoBackend` holds its closure to an allowlist of eight packages outside the
standard library). `enforce/cgroup`, `enforce/landlock` and `enforce/observe` still reach yaml.v3 through
`pkg/spec`, and `capture/uprobe` still reaches it and both decoder modules (measured with `go list -deps`,
linux/amd64, with and without tegobpf), so the item stays open.

*Amended 2026-10-05, the list above.* It named `ask`, the Docker proxy and the BPF programs only,
while SECURITY.md also named `supervisor`, `internal/policy/decide` and the BPF loader, and ADR 0014 counted
`enforce/*`; on 2026-10-05 SECURITY.md was changed to say "the authenticated ask broker and policy compiler" are
TCB without naming a package or changing this list. Code added on 2026-10-04 runs in the launcher,
as root in the root tiers, on input the governed agent controls: `dnsbroker` parses its DNS queries and decides with
`pkg/policy/dnspolicy`; `capture/forwarder` decides `net.http` and `net.proxy` with `pkg/policy/httppolicy`
before any upstream work, and parses CONNECT tunnels and WebSocket frames (`websocketFrames`) itself, with HTTP/2
framing left to the standard library. Both are on the list now, with the policy packages, `ask` named by its path,
and the packages the other lists already counted; SECURITY.md carries the same list. The policy compiler stays off
it, as agent-contract I6 states: it makes no mutating syscall, though under `sudo tego run` it runs as root
before launch. It joins the list when ADR 0031 (proposed) moves its I/O into `internal/policy/compile`. What the
list does not yet meet, measured with `go list -deps -tags tegobpf` on 2026-10-05: `dnsbroker` (x/net, x/sys),
`ask` (x/sys) and the four `pkg/policy` packages (none) keep the dependency rule; `capture/forwarder` does not,
reaching `andybalholm/brotli` and `klauspost/compress` through `capture/httpstream`, as `capture/uprobe` does, and
`gopkg.in/yaml.v3` through `pkg/spec`; the Open condition above now covers it as well. Fuzz targets exist for the
DNS wire parser (`FuzzDNSWireBoundaries`) and the forwarder's `/proc` and sock_diag readers, not for
`websocketFrames`, the CONNECT request path, `httppolicy.CanonicalPath` or the ask broker's command decoder; the
fuzz rule above names readers of another process's memory, so none of these breaks it, and an external review
would cover them as TCB.

*Amended 2026-11-01, the list above.* `internal/runtime/mcprelay` joins it, with `pkg/policy/mcptool`, the decision core
it decides with. The relay runs in the launcher, as root in the root tiers, and parses traffic the governed agent
controls: JSON-RPC over HTTP, and over the shim that stands in for a stdio server (ADR 0126 §4). SECURITY.md carries
the same list.
`go list -deps` on 2026-11-01, with and without tegobpf: it reaches x/sys and x/net, and `gopkg.in/yaml.v3` through
`pkg/spec`, so the Open condition above covers it as well. `FuzzWireLine` covers its wire form, and
`internal/runtime/derive/mcp` has fuzz targets for the framing it reads.
