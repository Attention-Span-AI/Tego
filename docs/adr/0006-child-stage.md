# ADR 0006: a re-exec child stage applies Landlock and seccomp before exec

Status: accepted 2026-09-21.
Amended by ADR 0042 (accepted 2026-10-05): the 2026-09-21 note's file-capability re-exec is conditioned.
Decision: `tego run` re-execs `tego __child`, which on one locked OS thread joins the cgroup, sets env, drops uid, sets `no_new_privs`, applies the Landlock ruleset, installs the seccomp filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, sends the notify fd to the parent over `SCM_RIGHTS`, then execs the agent.
Why: Go cannot run code between fork and exec; seccomp filters and Landlock domains survive `execve`; `NEW_LISTENER` cannot be combined with `TSYNC` (EINVAL without `TSYNC_ESRCH`), so one thread that execs immediately is the correct shape; the same pattern is used by runc and bubblewrap.
Consequence: setuid binaries do not work inside a run unless `privileged: true` and a root launcher; the child stage is part of the trusted computing base.

Amended 2026-09-21: step 7 as written traps itself (the filter's own `sendmsg` rule would catch the `SCM_RIGHTS` message). The child writes the notify fd number to the control pipe and the parent takes the fd with `pidfd_getfd` on the child's pidfd (`clone3(CLONE_PIDFD)`), starting `NOTIF_RECV` before acking. The parent sets `PR_SET_CHILD_SUBREAPER` before forking; the child sets `PR_SET_PDEATHSIG` after its last credential change and execs `/proc/self/exe`. Under `privileged: true` the stage applies Landlock and seccomp before dropping uid, while `CAP_SYS_ADMIN` is held. Landlock ABI 8 adds `LANDLOCK_RESTRICT_SELF_TSYNC`; the single-locked-thread stage does not need it.

Amended 2026-09-21 (second): the stage drops every capability and sets `PR_SET_DUMPABLE=1` before writing the notify fd number, because a stage re-exec'd from a file-capability binary or dropped from root is non-dumpable and `pidfd_getfd` refuses non-dumpable targets without `CAP_SYS_PTRACE` (verified by reproduction: the `SCM_RIGHTS` variant deadlocks in `seccomp_do_user_notification`; the pidfd variant receives `execve` as its first notification and completes). The filter carries an arch/compat-ABI guard. Error codes without `no_new_privs` and `CAP_SYS_ADMIN`: Landlock `EPERM`, seccomp `EACCES`.

Note 2026-09-29: the subreaper also reaps what it adopts. `Child.RunReaper` waits for exited descendants in the run's cgroup (not the main child), so their zombies do not stay charged to `pids.current`.

Note 2026-09-29 (second): the reaper finds those descendants through `/proc/self/task/*/children`, which exists only with `CONFIG_PROC_CHILDREN`. On a kernel without it, it scans `/proc/<pid>/stat` for `PPid` equal to itself instead, so it does not silently find none.

Note 2026-09-30: the stage is cloned into the run cgroup after `pids.max` is written, so its Go runtime threads count against `limits.pids`; a cap below about 6 kills it before the handoff with the runtime's `failed to create new OS thread`. The run fails closed before `run_start`, and `runtime.ErrStagePidsCap` names the cap when the cgroup's `pids.events` `max` rose (runtime-launch.md case 3).

Note 2026-09-30 (second): "in the run's cgroup" includes its sub-cgroups. `pids.current` counts the scope hierarchically, and a process of the run can move an orphan into a sub-cgroup of its scope where no Landlock rule covers `/sys/fs/cgroup` (`--observe` with an unprivileged launcher), so the reaper takes a zombie whose cgroup is the run's or a descendant of it, as `cgroup.kill` and `Remove` already do.

Note 2026-09-30 (third): a privileged stage's uid drop sets the supplementary group list to the target gid alone (`setgroups([gid])`); the invoking user's other groups are not carried, so a `sudo tego run` agent lacks the `docker`, `video` or project groups the same command keeps unprivileged. Deliberate and fail-closed: such groups grant through sockets and device nodes what Landlock does not bound (runtime-launch.md R4a).

*Amended 2026-10-05 (ADR 0042 (3)):* the second 2026-09-21 note's "a stage re-exec'd from a file-capability
binary" is conditioned by ADR 0042 (3)(c): such a binary is refused before the stage is dispatched
(`cli.GuardPrivilege`, the first call of `cmd/tego`). The stage's capability drop and `PR_SET_DUMPABLE=1` stay as
written, because a stage dropped from root needs them.

*Amended 2026-10-18 (doc audit):* the Consequence's `privileged: true` is, in the contract as built, `setuid: true` (ADR 0033; `pkg/spec/agent`). The contract's `exec.privileged` field is a different, schema-only list. ADR 0033 (no_new_privs at every tier) also bears on this stage.
