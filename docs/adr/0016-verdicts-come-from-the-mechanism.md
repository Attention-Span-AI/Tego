# ADR 0016: a ledger verdict is what a Tego mechanism answered, never what policy predicts for another mechanism

Status: accepted; step 1 implemented 2026-09-24, step 2 implemented 2026-09-29, step 3's producer table implemented 2026-09-29 (notes below). Step 1 in its simplest form: the supervisor's advisory verdict for a modification is the Landlock union over the compiled table (any enclosing write entry grants), reads skip implicit entries and an unenforced deny_read refuses nothing at tier 1; Evaluate's tier-2 modifications use the union; the observe recorder's inferFS no longer stamps refused on a write under a nested deny_read. The scoped Prepare-time grant plan in ADR 0028 S1/S3/S5/S6 was implemented in the 2026-10-04 amendment; remaining conformance and engineering migrations are separate open obligations. Proposed 2026-09-23. Amends supervisor R15 (advisory verdict), enforce-cgroup-observe R9, R10, §2.3 and §2.4, REASON-CHANNEL, and spec/record/v1 (the producer table).
Amended in part by ADR 0048 (accepted 2026-10-06): (4)'s producer table gains the supervisor's command-rule refusals and, with ADR 0048's P2, the plane's pin refusals and kills, folded fail-closed by `(run, seq)`.
Amended in part by ADR 0044 (accepted 2026-10-16, not built): (4)'s producer table gains the supervisor as the producer of a trace-gated exec's terminal line at every tier (an approved exec ask, a pass, a standing answer, and every exec under `exec.assurance: verified`), the kernel's `sched_process_exec` record of the same attempt consumed by the attempt marker so the action keeps one line.

Decision: (1) A verdict on a ledger line is one of: the answer the producer gave itself (the supervisor's own errno or the real result of a connect or send it performed or relayed; a fanotify listener's own response; the return of a Tego kernel program); the return of the kernel's LSM chain read by an fexit program on the security_ function that ran it, attributed to the plane by its rule_idx or to the run's Landlock domain by the run tier's model; or observed. A chain return that no Tego mechanism explains (no plane rule_idx and no refusing entry in the tier's model) is observed, with the errno and by: other in the payload, never refused with a Tego reason: REASON-CHANNEL's reason set is closed and names Tego's refusals, and the reason channel must not tell the agent Tego refused what another LSM refused. No producer stamps a verdict by re-evaluating policy on behalf of another mechanism.
(2) Tier 1: seccomp's CONTINUE returns nothing, so for an action the supervisor continues, its verdict is the landlock model's prediction over the plan the builder installed (ADR 0028, computed at Prepare over the held descriptors): grants union along the path, and a deny_read the plan marks unenforced refuses nothing. The capability line keeps calling the tier-1 record advisory, and ADR 0017 holds the model to the kernel.
(3) Tiers 2 and 3: the recorder's kernel programs become fexit programs, carrying the chain's signed return, on every security_ function where the run's inherited Landlock domain can refuse: security_file_open, security_path_mknod, security_path_mkdir, security_path_rmdir, security_path_unlink, security_path_rename, security_path_link, security_path_symlink, security_path_truncate, and security_file_truncate where the kernel has it (6.2+). security_socket_connect stays fentry: it returns before sock->ops->connect, where connect4/6 decide, so its return never holds the cgroup verdict; an io_uring connect's verdict comes from R5's reason breadcrumb. The verdict means exactly the LSM chain's return, which on kernels up to 6.12 also includes the fanotify permission answers (security_file_open calls fsnotify_open_perm after the chain there, not from 6.13), and on no kernel includes IMA's ima_file_check or any check made after the security_ function returned. One action, one line: an O_CREAT create is the path_mknod line only when it refuses, and otherwise the file_open line with created: true; an allowed O_TRUNC open of an existing regular file is held in task storage by file_open's fexit and emitted once with the truncate hook's result by that hook's fexit (a held record not consumed is emitted by the task's next recorded event or its exit); path_mknod's allow line is emitted only for a call that is not an O_CREAT open, told apart by the syscall number (bpf_task_pt_regs, 5.15+); where that helper is absent, a successful mknod(2) of a regular file is the one unrecorded shape, stated per kernel. Files the kernel opens on a task's behalf for a stacking filesystem are skipped: FMODE_BACKING files (6.6+), and below 6.6 the overlay real files open_with_fake_path opens (FMODE_NOACCOUNT), whose path is the user path the task's own open already recorded. observe.inferFS is deleted; dirIndex keeps only path reconstruction. rule is attribution only: the plane's rule_idx (ADR 0024, read from task storage), else the tier model's nearest refusing entry. Refusals are emitted under record: off too. R9's verdict: inferred is withdrawn. Under lockdown=confidentiality the recorder loads a variant without kernel probe reads (direct BTF loads and bpf_d_path); fields that need a kernel string read are empty and the run gets gap what=record why=lockdown.
(4) One producer per (tier, syscall kind, outcome), written as a table in spec/record/v1. Tier 1: the supervisor for every notified kind. Tiers 2 and 3 with the kernel record readable: the supervisor for what it answers itself (connects and sends it performs or relays; its own refusals: deny_write, unreadable arguments, unmatched or anonymous execs, socket families); the kernel for every kind in item 3's list after a CONTINUE, for successful execs (sched_process_exec), and for plane refusals on hooks without a recorder fexit (ADR 0024). The fanotify fallback's listener for the opens the core routes to it, the recorder dropping its own line for exactly those opens by the same core function. The kernel's connect record only for io_uring: true runs. When the kernel record for a kind is unavailable (lockdown fields, or before ADR 0026 the second concurrent run of a build), the supervisor produces that kind with the run tier's own model (root intersected with landlock, or the fanotify model in the fallback), never tier 1's, or observed when the model cannot decide, and the run's gap says so. supervisor.Options.KernelRecords is a per-kind set.
(5) With one producer per action, drift and status count lines as actions, and ADR 0017 asserts no action has two verdict lines. No correlation key is added to record v1.

Why: [measured, 64 contracts x 12 fs actions] Tier 1 on 6.17: the seccomp line says refused for 52 of 768 actions that succeeded; last-refusal.json and drift repeat it. Tier 2 in the 6.17 guest: the kernel recorder is wrong on 66 of 768, the seccomp line on 28, and 483 actions produced 2 or 3 lines.
[documented, code] supervisor fs.go fsVerdictIn is nearest-wins while tier 1 is Landlock's union, and fs_test.go:69 pins the wrong answer; observe/rules.go inferFS stamps verdicts; trace_proc.bpf.c's five fentry programs run before the chain and stamp TEGO_V_OBSERVED.
[documented, security/security.c at v6.12 and v6.13, checked today] v6.12's security_file_open returns fsnotify_open_perm(file) after call_int_hook; v6.13's is call_int_hook alone.
[documented, fs/open.c v6.6 and fs/backing-file.c v6.8/v6.12, checked today, fs/open.c v6.1 open_with_fake_path] Overlay real files reach security_file_open in the agent's task; at 6.6 and 6.7 f_path is the user path, from 6.8 it is the real path.
[documented] The recorder hooks only file_open, path_unlink, path_rename, path_mkdir and socket_connect; the filter also notifies creat and O_CREAT, rmdir, link and symlink, and Landlock refuses a create in path_mknod before any file_open, so with the supervisor skipped those refusals would have no producer.
[measured, 1536M/2-vCPU guests, paired rounds, run_set miss] Per host open, 7 recorder programs cost +46 ns (fentry) vs +130 ns (fexit) on 6.17, +61 vs +145 on 6.8, +88 vs +103 on AL2023 6.1; per 5-op fs iteration +367/+565/+431 ns vs +571/+928/+723 ns; detach time is the same. [documented, kernel/bpf/trampoline.c] An fexit or fmod_ret trampoline calls the original and holds the image's percpu_ref; fentry-only does neither.
[documented, kernel/trace/bpf_trace.c at v5.14, checked today] Task-storage helpers are offered to tracing programs.
[inference] One producer per action removes the multiplicity without a schema change; a correlation key would be ambiguous exactly for concurrent threads.

Security argument: Enforcement is untouched: fexit programs cannot change a return value and the supervisor's answers do not change. The reason channel stops telling the agent that actions which succeeded were refused, still receives every Tego refusal (every producer emits refusals under record: off), and never claims another LSM's refusal as Tego's. At tiers 2 and 3 the verdict comes from the mechanism, so a wrong model can mislabel rule but not flip a verdict. A missing kernel record falls back to the tier's own model with a gap, never to tier 1's prediction, which after ADR 0024 would read allow for what the plane refused. A missing producer is a gap, never a silence (ADR 0015).

Options considered: Chosen: the tier's own model at tier 1, fexit at tiers 2 and 3, one producer per (tier, kind, outcome).
Rejected:
- Keep inferring and fix the three copies: drift recurs, and an inference cannot see Landlock's or another LSM's verdict.
- Other producers writing observed lines: keeps 2-3 lines per action.
- A correlation key in record v1: ambiguous for concurrent threads.
- verdict: inferred: a guess every view must discount.
- fexit on security_socket_connect: a CALL_ORIG trampoline on every host connect for a return that never holds connect4/6's verdict.
- An unexplained refusal as refused and unattributed: a refused line must carry a reason from the closed set, and the reason channel would attribute it to Tego; the form observed, errno, by: other was chosen.
- fexit only on file_open, bprm_check, path_unlink, path_rename and path_mkdir, with the plane emitting the rest: Landlock's refusals of creates, rmdir, link, symlink and truncate would have no producer.
- The tier-1 prediction as the fallback at tiers 2 and 3: reads allow where the plane refused.

Consequence: The tier-2 record carries the chain's own verdict, Landlock's included, one line per action, with the unexplained refusals of other LSMs visible as observed. While a build is attached every host process pays the fexit cost: +130/+145/+103 ns per open on 6.17/6.8/6.1 instead of +46/+61/+88 for fentry, and +571 to +928 ns per 5-op fs iteration (measured). ADR 0022's linger bounds how long that lasts. The recorder goes from five trampolines to ten; in fmod_ret mode each shares the plane's trampoline. Tier-1 lines for writes under an unenforced deny_read now read allow, which is what happened.

Implementation plan:

Step 1 (S; after ADR 0028 S1, together with 0028 S2): enforce.Handle gains GrantPlan() (the Prepare-time plan from the core). The supervisor's fs verdicts call the core's landlock model at tier 1, and the tier's model at tiers 2 and 3 for kinds with no kernel record. fs_test.go:69 flips to allow. A contracttest table covers the 64x12 grid. Acceptance: ADR 0017's fs grid at tier 1 on this host shows zero verdict mismatches.
Step 2 (L; after ADR 0026):
- First load fexit on the ten functions on every row: GUEST (6.17) and MATRIX (5.14, 6.1, 6.8, 6.12 twice, 7.0).
- bpf/trace_proc.bpf.c: fexit programs (file_truncate optional by BTF presence) with 6.1 prototypes plus int ret. Signed ret goes into tego_ev_fs and tego_ev_fsop, with the parity test in internal/bpf/types.go. The tego_recording check moves after ret.
- A task-storage map, tego_task_scratch, for the held O_TRUNC open and, after ADR 0024, the plane's rule_idx.
- The backing-file skip, with per-kernel flag constants chosen by BTF presence of struct backing_file and checked against each matrix kernel's include/linux/fs.h.
- The lockdown variant.
- internal/runtime/observe maps ret 0 to allow. A -EACCES, -EPERM or -EXDEV explained by the model or by rule_idx maps to refused with the op's reason. Anything else maps to observed with the errno and by: other. Delete inferFS.
- Tests as root in GUEST and on MATRIX: the fs grid at tier cgroup with zero verdict mismatches and at most one line per action; an overlayfs cell (one line, the user path); O_CREAT, O_TRUNC and mknod(2) cells; ADR 0017's third-party fanotify cells on a 6.12 row (observed, by: other) and on 6.17 (the line reads allow, because the listener's refusal is outside the chain; the cell documents it); a lockdown=confidentiality boot of 6.17 records the gap.
- Measure attach, detach and per-call cost at ten fexit programs on 6.8, RHEL 9 and 6.1.
Step 3 (S): the producer table in spec/record/v1/README.md. KernelRecords becomes a per-kind set, set by internal/runtime from the recorder's capabilities. The reason stage takes refusals from every producer. drift and status count actions.
Docs:
- supervisor R15.
- enforce-cgroup-observe R9 (inferred withdrawn), R10, §2.3 and §2.4, and the cost table.
- The record README.
- REASON-CHANNEL (observed with by: other is not a refusal).
- The drift docs.

*Amended 2026-09-29 (T1, TIER3-PLAN §11):* the text is final; steps 2 and 3 (the fexit recorder and the producer
table) are being built, and neither was on master when this note was written (trace_proc.bpf.c's programs are still fentry, and
observe keeps its inference, now `decide.InferFS` after ADR 0028 S1). T0 (ADR 0024's notes) confirms (3)'s lockdown
variant is needed on every kernel, not only old ones: lockdown=confidentiality refuses `bpf_probe_read_kernel` at
load on 6.17 too, so the recorder's confidentiality build must use no probe read at all.

Implementation note, 2026-09-29 (step 2, and step 3 in part). Built:
- bpf/trace_proc.bpf.c: fexit on the ten functions of (3), each declaring its whole prototype (identical 5.14 through 7.0, security/security.c checked at v5.14, v6.1, v6.8, v6.12, v6.17 and v7.0) and then `int ret`, since an fexit program's return is the slot after the last argument (internal/bpf TestAttachTargetsResolve fails a shorter declaration). security_socket_connect stays fentry. The signed return is `ret` in tego_ev_fs and tego_ev_fsop with `ret_ok`, in what were pad bytes, so the layouts keep their sizes and TEGO_EVENTS_VERSION stays 1 (C/Go parity in internal/bpf types.go and parity_tegobpf_test.go). Five kinds (mknod, rmdir, link, symlink, truncate, 14 to 18) are tego_ev_fsop records. The recording check moved after ret: a refusal is recorded under record: off.
- tego_task_scratch (TASK_STORAGE, pinned by name) holds the O_TRUNC open for the truncate hook's return, and also the O_CREAT create: security_path_mknod of a regular file with no device is held and dropped by a security_file_open of the same dentry (pointer, else parent and d_name.hash_len). This replaces the syscall-number test of (3), which needed bpf_task_pt_regs and a per-architecture object: may_o_create asks path_mknod before it knows the file exists and a refusal there only clears O_CREAT, so a refusal is the action's only when no open follows, which the hold decides on every kernel; a mknod(2) of a regular file is recorded (late, at the task's next event), not the unrecorded shape (3) stated. Recorded as the allowed mknod the chain answered: an O_CREAT open that security_inode_create or the filesystem fails after, and an O_EXCL create of a file that was there.
- The backing-file skip tests FMODE_NOACCOUNT (1 << 29 on every kernel from 5.14 through 7.0, include/linux/fs.h checked at v5.14, v6.1, v6.5, v6.6, v6.8, v6.12 to v6.17 and v7.0) instead of per-kernel FMODE_BACKING constants: FMODE_BACKING moved from bit 25 to bit 24 in 6.14, every backing file carries both (alloc_empty_backing_file, 6.5+), and below 6.5 open_with_fake_path's overlay file carries FMODE_NOACCOUNT. The flag also skips kernel_file_open's files, which no descriptor table holds.
- security_file_truncate's program is left out of the load where the kernel's BTF lacks the function (below 6.2); doctor's D7 row is optional there.
- internal/runtime/observe: the line's verdict is the chain's return through decide.ChainFS (0 allow; -EACCES, -EPERM or -EXDEV the model explains, refused with the model's reason; anything else observed, `by: other`, `errno`). decide.InferFS is kept, not deleted as (3) says, since a kernel record without the return still needs a verdict: it explains a refusal, and decides a record that carries no return (`ret_ok` 0), and every fs line says which (`verdict_from: chain|model`, additive within v1). A read under an unenforced deny_read keeps the model on every kernel: the listener answers it, outside the chain from 6.13. Under record: off the recorder keeps the refused lines.
- Tests: bpf/tests (fexit sections, the return declared and stored, record: off gated on ret == 0, wakeups of the held flush); internal/bpf (layout parity, attach types, argument counts); observe chain_test.go (decoder and recorder cells); as root in the 6.17 guest, observe TestIntegrationChainReturnIsTheVerdict: a Landlock-refused read, O_CREAT create and unlink are recorded refused from the chain's -EACCES with the contract's reasons, an O_TRUNC open is one line, a created file's open drops its held create (created: true), a truncate Landlock refuses under an entry the contract grants is observed, by: other, errno 13, and under record: off only the three refusals are recorded; every observe and doctor root test passes with the ten fexit programs (doctor: 29 of 29 hooks).
Open from step 2: the overlayfs, fanotify-on-6.12 and mknod(2) cells on the matrix rows; the 64x12 grid at tier cgroup; the attach, detach and per-call measurement at ten fexit programs on 6.8, RHEL 9 and 6.1. Step 3's producer table and the per-kind KernelRecords (which producer writes which line) belong to the ledger-line ownership work; the reason stage already mirrors a refused line from any producer, and an observed `by: other` line is mirrored by none.

Implementation note, 2026-09-29 (step 3, the producer table). One line per action at tier 2, read off ADR 0017's conformance cells (supervisor R7a, enforce-cgroup-observe R9):
- The recorder writes the line of every fs action its hooks see, with the chain's verdict, whenever it reads the run (supervisor Options.KernelFS, the runtime's answer as for connects, under every record mode). The supervisor writes none for such an action it continued, and hands the recorder its naming before it answers (Loop.ContinuedFS, keyed by thread and the record's own stamp — the thread's last action handed over before it — and checked by operation and each end's final component); the recorder names by it a record its directory index cannot, the chain's return staying the verdict and the supervisor's verdict the model that explains a refusal. KernelRecords is this per-kind set: a predicate over (enforced by the supervisor, chmod) rather than a set the recorder reports, since the ten fexit hooks are one load.
- The supervisor writes its own refusals (deny_write, R15d, fail-closed), mode changes (no recorder hook) and every exec: sched_process_exec carries no mechanism's verdict and names the spelling, while the supervisor decides each exec on its image. This departs from (4)'s "the kernel for successful execs" until an exec record carries the grant it ran under.
- The fanotify listener writes the line of an open it refuses after Landlock let it through; the supervisor (by decide.Evaluate's Landlock column) and the recorder (by decide.ListenerOpenRefused, unless the chain returned EACCES or the mount is unmarked) write none.
- ADR 0017's baseline has no ledger entry left; the drift and status counting of actions is not changed here.

Note, 2026-09-29: the hold is matched to its action. A held O_TRUNC open keeps its dentry and is taken only by a truncate of that dentry; an open that failed after security_file_open (the filesystem's ->open, fanotify from 6.13, security_file_post_open) is otherwise emitted as the allow the chain answered, and the task's next truncate of another file is its own line instead of lending the open its return. A held create is dropped only by a security_file_open whose f_flags carry O_CREAT (kept there although lookup_open clears its copy), so a mknod(2) followed by a plain open of the file is recorded, as the step-2 note says. Kernel cell: observe TestIntegrationHeldRecordsAreTheirOwnActions (a kernfs O_TRUNC open refused in ->open, then truncate(2); mknod(2), then open).

Implementation note, 2026-09-29 (the lockdown=confidentiality variant, built): the recorder's object is compiled twice, and the build without any kernel probe read (`tracerd`) loads under lockdown=confidentiality wherever the kernel's BTF has `bpf_rdonly_cast` and `bpf_loop` (ADR 0024's tier-2 note has the measurements and the condition for a kernel without them).

Implementation note, 2026-09-29 (TIER3-PLAN T9; enforce-plane §2.8). (3)'s "the plane's rule_idx, read from task
storage" is built for step A: the plane's decision carries the object it was on, the recorder's object declares the
plane's `tego_plane_scratch` and pins it beside the plane's, and each fexit on `security_file_open`,
`security_path_unlink`, `security_path_rmdir`, `security_path_rename` and `security_path_link` takes the decision for
its own call by hook and object and stamps a plane refusal, with the chain's `-EACCES`, on its record: the action's
one line, `mechanism: plane`, the mode, the rule `rule_idx` names through the plane's rows. The plane writes its own
sample only on `bprm_check`, which no fexit wraps. (4) is amended for tier 3, with the evidence it asked for: the
table's departure, "the supervisor for every exec, until an exec record carries the grant it ran under", ends where
the plane decides the run's execs, because `bprm_check` decides on the image the kernel loads and records the grant
(`rule_idx`) that `sched_process_exec` then carries. The supervisor's allow of an exec it continues is a prediction
made on its own resolution of the image; the plane overturns it when the image changed since, when a walk fails closed
or when a row's identity no longer matches, and the supervisor's line would then say allow for a refused exec beside
the plane's refusal: two lines, one wrong. So with the plane deciding execs (`enforce.DecisionPlaneReporter`) and a
recorder reading the run, the supervisor writes no line for an exec it continues (`supervisor.Options.KernelExecs`),
and the kernel writes the exec's one line: the plane's refusal sample, or `sched_process_exec` named by the plane's
rule (`observe.Options.SupervisorExecs` false). The supervisor keeps the lines of the execs it refuses or answers
itself, which never reach the kernel. Residual: an exec the supervisor continued that the kernel fails outside the
plane has no exec line. Held by supervisor `TestExecContinuedIsTheKernelsLineUnderThePlane`, runtime
`TestKernelRecorderOwnsExecsUnderThePlane` and, in the 6.17 guest in both modes, observe
`TestIntegrationPlaneRefusalIsOneLine`.

Note, 2026-09-29: the layout note above ("TEGO_EVENTS_VERSION stays 1") held when ret went into pad bytes. Since then `tego_ev_fs` dropped its reserved, always-empty `path2` (592 to 336 bytes, every open on the ring and every held O_TRUNC/O_CREAT record), and TEGO_EVENTS_VERSION is 2 (enforce-cgroup-observe §2.3). The kernel ring layout is internal; spec/record/v1 is unchanged.

Implementation note, 2026-09-30 (TIER3-PLAN T16's naming; enforce-plane §2.15). (3)'s fsop records name a file by
the parent's `(dev, ino)` and the final component, which the directory index turns into a path only for directories
an entry is; everywhere else the supervisor's naming of the notification it continued (`ContinuedFS`) filled the
line. Once the plane's filter leaves those mutations unnotified (T16) there is no such naming, so for a run a plane
mode decides the fsop record now carries each side's parent directory by its path, walked in the recorder's own
fexit (`trace_proc` `tego_dir_walk`): `d_parent` to the mount's root, `mnt_mountpoint`/`mnt_parent` across mounts,
to `current->fs->root`, as `d_path` walks, with each level's `d_seq` read before its parent and name and compared
on a second pass, so a component renamed meanwhile fails the walk instead of joining two paths. `bpf_d_path` was
evaluated and cannot do this: a tracing program may call it only at `btf_allowlist_d_path`'s functions
(`security_file_open`, `security_path_truncate`, the same set at v5.14, v6.1 and v6.17), and an LSM program only at
a sleepable hook, which the `path_*` hooks became in 6.8. A walk that cannot prove its path (longer than 256 bytes or
64 components, raced, disconnected or outside the task's root) is never used: the line takes the index's name, or
the marked `dev:ino/name` with the `dir-unresolved` gap. The line's verdict is still the chain's return and its rule
still the plane's `rule_idx` on a plane refusal, and the model's grant name (compile --test's) on an allow. The
recorder says so (`runtime.PathHookNamer`), which is T16's gate. Held by observe `TestRecorderNamesWalkedPathHooks`
and, as root in the guests, cgroup `TestPlaneRunDropsAndNamesByPath`. Amended the same day: each crossing's parent
mount and mountpoint are rechecked on the second pass as well (a mount moved meanwhile fails the walk, `mount_lock`
being no BTF symbol), and a fetch atomic, fully ordered in every JIT, fences the sequence reads as `smp_rmb` would
(arm64 reorders plain loads); enforce-plane §2.15's conditions 1 and 2 are closed.

Note, 2026-09-30 (the overlayfs cell). (3)'s one line per action did not hold for a first write to a
lower overlayfs file: overlayfs' copy-up opens the lower file and the new upper one with a plain `dentry_open`, in
the agent's task, on its private clones of the layers' mounts, and those files carry no `FMODE_NOACCOUNT`, so the
recorder wrote two more open lines, named relative to the clone's root. `tego_file_open` now skips a file on a
mount whose `mnt_ns` is `MNT_NS_INTERNAL`, as the plane already did (enforce-plane §2.7 condition 1), after taking
the plane's scratch and before the hold (enforce-cgroup-observe R8). Held by bpf/tests
`TestRecorderSkipsPrivateCloneOpens` and, as root in the guest, observe `TestIntegrationOverlayCopyUpIsOneLine`;
the overlayfs cell listed as open from step 2 is that test, on the matrix rows still to run.

*Amended 2026-10-05 (ADR 0041, proposed):* (4)'s "the supervisor for ... its own refusals:
deny_write" no longer has a tier-1 or listener-only tier-2 case. Since 2026-10-03 a non-empty built-in
`deny_write` set refuses launch at tier landlock and at tier cgroup without a plane (agent-contract R20,
enforce-landlock R5a, supervisor R15c), so a run in which the supervisor refuses a `deny_write` target has a
plane, which decides those targets race-free in the kernel. Whether the plane-less tiers keep that refusal or gain
a recorded opt-out is [ADR 0041](0041-race-free-supervisor-decisions.md) D8 (open when this note was written; decided in the note below).

*Amended 2026-10-05 (ADR 0041 accepted, D1 decided (a)):* the note above holds only under `fs.assurance: kernel`. By
default (4)'s case is back: at tier landlock and on tier cgroup's listener the supervisor refuses a `deny_write`
target itself (supervisor R15c), and its line is that mechanism's answer, best effort against a racing path, which
compile discloses per target and run_start records as `best_effort` `deny_write/default`.

*Amended 2026-10-05:* an addressed datagram that a kernel program
of the run decides by destination (tier 2's `cgroup/sendmsg4`, `sendmsg6` and `sendmsg_unix`, and the plane's step-D
`socket_sendmsg` below 6.7) was continued by the supervisor with a `best_effort` line, so (1) did not hold for it: an
unlisted destination read refused with `best_effort` beside the kernel's enforced `EPERM`, and a unix name spelled
non-canonically, which the supervisor cleans and admits and the programs refuse, read allow. Measured first in the
6.17 guest (`TestTier2DatagramLineIsTheKernels`, UDP and unix alike). The supervisor now refuses, with the program's
own errno, a datagram the program would refuse (supervisor `Options.KernelDatagrams`, from the tier's
`Handle.KernelDatagrams`), so the line is the answer it gave itself, (1)'s first case, and the datagram's only one;
an admitted datagram is still continued, and its line stays `best_effort`, the producer disclosing that the kernel
decides its own copy. tier-audit's D7 had chosen to relay such datagrams and read the real errno. Not done: a unix
datagram sent from the supervisor carries the supervisor's real uid and pid to a receiver reading `SCM_CREDENTIALS`,
and is ADR 0041's rejected alternative 7 besides; a UDP relay must refuse the control messages (QUIC's GSO segments,
ECN), `MSG_ZEROCOPY` and sizes past `sendBytes` that tier 2 delivers today, or continue those and keep the split for
them. The refusal costs no syscall on an admitted datagram and one `SO_DOMAIN` read on a refused one. Residual: a
`sendmmsg` batch keeps its best-effort lines, and a corked UDP socket's append, which the kernel sends past
`sendmsg4`, is refused when it names an unlisted address.

*Open item 2026-10-19 (ADR 0017's fs grid):* every verdict the grid's lines carry agrees with
the kernel, but some refusals' lines name an entry that refused nothing. On the lsm plane (tier cgroup in mode lsm,
tier bpflsm) a refused action beneath a `watch` names `fs.watch[...]` where compile --test names the entry that
refuses (no entry, or the deny_read above the watch), and tier cgroup's fanotify listener names a refused read beneath
a watch inside a deny_read alike; a rename the plane refused can name its destination's entry where compile names its
source's. A watch only records, so such a line misstates which rule refused, a rule-accuracy question for this ADR's
"the verdict is what the mechanism answered" as well as a naming one. The conformance suite counts these as known
naming classes (test/conformance/naming.go) until the naming question is settled; nothing else about the verdict changes.

### Recording amendment, 2026-11-04: shared trampoline miss counters

The Fedora 7.0 matrix's 32-run round completed in 7.5 seconds but lost watched opens without a ring-buffer drop.
A local default-LSM KVM reproduction lost 55 watched opens while `tego_file_open` gained 124 `recursion_misses`.
The trampoline can skip a preempted tracing program before its run-set lookup (GAPS C53); changing timeouts cannot
restore those callbacks. This also happens with the LSM plane: it is the recorder's fexit callback that is skipped.

The recorder resolves its build's executing tracing program instances from the pinned links and holds both
references. It samples their cumulative miss counters before launch and reads them again after its final drain. A positive delta is a record gap,
`bpf-trampoline-miss/shared-build`. The count is shared-build skipped executions in that window, including other
runs and ungoverned tasks. It is neither an exact per-run loss count nor an upper bound on every record suppressed:
one skipped exit may also lose held records. An executing instance that cannot be established, an attachment that
changes during the window, or a counter that cannot be read or goes backwards yields
`bpf-trampoline-counter-unavailable`. No callback is replayed and no verdict is inferred for a missing callback.
Receipts and views keep coverage incomplete but call these reported skipped executions of shared tracing programs,
possibly from other runs or ungoverned tasks; they do not claim a known lost-event count. Merged overlapping run
windows may report the same skip more than once.
The concurrent watched-open test retains each run's bound and also requires the total missing watched opens across
all runs to fit one round-wide delta from the active file-open program alone. A barrier holds every agent before its
first watched open until that initial sample; a single shared skip cannot excuse one loss in each of two runs.
Other hooks' skips cannot excuse file-open loss;
duplicates, unexplained loss, ring/queue loss and missing metering still fail. Runs with no recorded misses retain
the exact-count assertion. Deciding and cgroup-tracking program misses and per-run loss attribution remain open C53 work.
