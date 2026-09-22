# ADR 0013: run lifecycle — lock, signals, PDEATHSIG, orphan sweep, hashed pins, self re-exec

Status: accepted 2026-09-21.
Refined by ADR 0015 (who starts a component and from where). Amended by ADR 0020 (accepted and built 2026-09-29: the reaper).
Decision: liveness is `flock` on `runs/<id>/lock`; terminal signals are not re-sent, `SIGTERM`/`SIGHUP`/`SIGUSR*` are forwarded, `stop_grace` then `cgroup.kill`; the child stage sets `PR_SET_PDEATHSIG` after its last credential change and the parent sets `PR_SET_CHILD_SUBREAPER`; supervisor death leaves descendants fail-closed (`ENOSYS` on notified syscalls) until the sweep; `run`, `stop` and `gc` sweep orphans and write `run_end reason=orphaned`; pins live under `/sys/fs/bpf/tego/<bpf_hash>/` with a build lock under `/run/tego/`; the child stage execs `/proc/self/exe`.
Why: kernel-generated signals bypass Landlock scoping and reach the foreground group already; `commit_creds` clears `pdeath_signal`; closing a notify listener fails pending syscalls with `ENOSYS` (verified); bpffs holds no regular files; cilium/ebpf's map compatibility check does not see struct layout.
Consequence: no pid or state files; `status` shows `lost` for a free lock with no `run_end`; exit codes follow `docker run` and `timeout` (spec/identity).
