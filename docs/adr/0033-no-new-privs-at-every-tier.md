# ADR 0033: no_new_privs at every tier by default; a root-tier contract may opt into setuid, never into loading kernel code or touching BPF

Status: accepted; implemented 2026-09-24: the stage sets no_new_privs after the privileged drop unless the contract's setuid: true; compile refuses setuid at tier landlock and warns elsewhere; the root-tier arm answers the six calls EPERM at tiers 2 and 3. Condition as built: no dedicated `setuid` capability row yet; the opt-in is recorded by the run's contract copy and contract_hash and warned at compile, and the row lands with the next capability-matrix change. Proposed 2026-09-23. Amends runtime-launch R4 and R4a, ARCHITECTURE §5, GAPS A7, agent-contract (a new top-level field), enforce-landlock's filter table and spec/backend/CAPABILITIES.md.

Decision: (1) The child stage sets no_new_privs at every tier. Under the privileged ordering (R4) Landlock and seccomp are still installed before the credential drop; no_new_privs is then set by prctl after the drop and PDEATHSIG, before the ack. (2) A contract at tier cgroup or bpflsm may opt out with top-level setuid: true: the stage then skips no_new_privs as R4 does today, compile warns, and the capability line's new row setuid is true. Tier landlock refuses the field (no_new_privs is mandatory there). GAPS A7's workaround (sudo inside a root-tier run) keeps working under the opt-in, and E70 (P2) stays the answer that needs no opt-in. (3) At tiers 2 and 3, whatever the opt-in, the filter answers bpf, init_module, finit_module, delete_module, kexec_load and kexec_file_load with SECCOMP_RET_ERRNO(EPERM), refusals Docker's default profile also makes. They are confinement, not policy verdicts, like the io_uring and openat2 ENOSYS arms: no ledger line, stated in CAPABILITIES. (4) Stated residual under setuid: true: a root agent keeps every root power that neither Landlock nor this filter mediates (setns, perf_event_open, ioperm/iopl and the like); the capability line says so, and SEMANTICS does not call such a run confinement against root.

Why: [documented, runtime-launch R4 and R4a] R4 skips no_new_privs whenever spec.Privileged, which every root tier sets, and R4a states the filter allows init_module, bpf, mount and setns, none of which Landlock mediates.
[documented] BPF_OBJ_GET checks inode permission, not file_open, so Landlock does not see a pinned-object open; a root agent can open tego_run_set and delete its row, which silences the plane (ADR 0024), the recorder and the cgroup programs for its run.
[documented, security/commoncap.c cap_bprm_creds_from_file] Under no_new_privs an exec gains no ids or capabilities, so setuid binaries and file capabilities do not elevate; tier 1 already runs this way (GAPS A7).
[inference] R4 skipped the flag as redundant for Landlock and seccomp, not to enable setuid; its only user-visible effect is that setuid binaries elevate, which is the hazard, so the safe default is the flag and the feature is an opt-in.

Security argument: Fail-closed by default: without the opt-in, no process in a run becomes root through an exec at any tier. With the opt-in, the filter still denies the syscalls that would let root inside the run disable Tego's kernel state or replace kernel code; they are errno returns in the filter itself, so they hold with a dead supervisor. The opt-in is on every run's capability line, never silent.

Options considered: Rejected:
- The filter refusals alone, with setuid elevation left on by default (the security review's minimum): closes the hole in Tego's own state but keeps every other root power one setuid exec away, by default.
- Refusing setuid binaries with exec rules: a path list cannot name every setuid file.
- Keeping R4 and stating the residual: a root agent can switch off its own run's enforcement.

Consequence: Agents that run sudo inside a root-tier run declare setuid: true until E70; compile's error names the field. Tiers 1, 2 and 3 agree on setuid binaries by default. Six more filter compares at tiers 2 and 3.

Implementation plan:

- internal/runtime/launch/child.go: step 4 at every tier (prctl after the drop), skipped only when spec.Setuid; ADR 0029's sys.RestrictSelf receives the caller's flags unchanged.
- pkg/spec/agent: top-level setuid: bool (compile error at tier landlock, warning otherwise); pkg/spec/backend and CAPABILITIES.md: row setuid, one golden pair.
- enforce/landlock filter.go: rootTierDenyArm over the six syscall numbers per arch, installed when the handle is built for tier cgroup or bpflsm.
- Tests: filter unit tests per arch (x86_64, aarch64 tables). As root in GUEST and on MATRIX at tier cgroup, with a setuid-root copy of a tiny helper (chmod u+s in the guest): without setuid: true it runs with the user's euid; with setuid: true it gets euid 0, and bpf(BPF_OBJ_GET) on /sys/fs/bpf/tego/<hash>/maps/tego_run_set, init_module, finit_module and kexec_file_load answer EPERM while the run's refused connect stays refused. internal/runtime sudo_integration_test.go and privileged_test.go move to the opt-in.
Docs: ADR 0033; runtime-launch R4, R4a; ARCHITECTURE §5 step 4; GAPS A7; agent-contract; CAPABILITIES; README threat model (root inside a run).
