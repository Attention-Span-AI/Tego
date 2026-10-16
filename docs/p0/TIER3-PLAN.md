# Tier 3 (bpflsm) implementation plan

§10 records the implementation through T16 on 2026-10-04. The design is ADRs 0024/0025; this plan sequences it. Dated acceptance measurements remain tied to the binary and kernel that produced them.

## 1. Goals and non-goals

**Goals**
- Tier `bpflsm` becomes Buildable. It is ADR 0024's decision plane in **LSM mode** (`BPF_LSM_MAC`) on top of tier 2 (cgroup network programs, recorder, rings, Landlock and the seccomp floor).
- Opens, execs and fs mutations of a governed run are decided in the kernel, on the object the kernel resolved: 0 or -EACCES, with a `rule_idx` for the ledger.
- The same C bodies also load as `fmod_ret/security_*`. That lets tier `cgroup` use the plane where `bpf` is not an active LSM (Ubuntu, WSL2), and fanotify becomes the probe-selected fallback (ADR 0021 (1)).
- Kill test 4 (go) passes at bpflsm. Tier cgroup fails it today: 21–25 µs per fanotify open vs about 0.2 µs per plane lookup, about 50 ms over go build's 2,500 opens. *Status 2026-10-06:* met on the 6.17 guest, not yet on the rows. Go passes 20 of 20 on a quiet 6.17 host at tier cgroup in lsm mode (1.52x) and at bpflsm (1.58x) (enforce-plane §2.18, §9's measured note). On the rows it is mixed: test/vm/README.md's tier-3 table (2026-09-30, before §2.18's changes) has 0 of 20 at bpflsm on debian-13, rhel-9 and al2023, and §2.18 has AL2023 6.1 between 1 and 19 of 20 with the host's load. Tier cgroup on the fanotify fallback still pays the per-open cost above.
- `compile --test` at bpflsm equals the ledger's verdict (ADRs 0019, 0028).

**Non-goals**
- No host-wide control. A program returns 0 unless `bpf_get_current_cgroup_id()` hits `tego_run_set`.
- No resistance to root: root can list (`bpftool prog`, doctor) and remove (`tego gc --builds`, unpin) every program. No kernel module, no LLM judging (ADR 0003).
- No LSM network hooks in P0: `socket_connect/bind/sendmsg` would double-decide what cgroup/connect, sendmsg and bind already decide per run (E54 P1). The one exception is step D: `socket_connect` and `socket_sendmsg` on AF_UNIX, loaded only below 6.7, where no cgroup program decides a unix name (T15).
- No `file_permission` (a cost on every read/write for passed-in descriptors only; a stated residual) and no `task_kill` (Landlock ABI 6 scopes signals). ptrace and `bpf` hooks stay E54 P1. *Amended 2026-10-05:* `ptrace_access_check`, `ptrace_traceme`, `bpf` and `key_permission` are built, and `socket_bind` (AF_UNIX) and `socket_listen` decide a declared `net.listen`; inet connect, sendmsg and bind stay with the cgroup programs (enforce-plane §1, §2.20).

## 2. Hook to contract-rule map (ADR 0024 (5))

| Hook | Contract rule | Step |
|---|---|---|
| `file_open` | fs `deny_read` (read), write/ask/`deny_write` for write-opens and O_TRUNC. Never exec rows (so PT_INTERP's ld.so passes). Skips FMODE_BACKING (6.6+). | A |
| `bprm_check_security` | `exec.allow` by inode plus parent-dir inode plus name bytes; `exec.anonymous`; a directly invoked loader. A `#!` stage passes. *Amended 2026-10-19 (ADR 0048 P2):* in a pinned run each stage is also checked against the exec's pin (image and interpreter identity): `pin-mismatch`, `pin-missing`, `exec-traced` | A |
| `tp_btf/sched_process_exec` (ADR 0048 P2, built 2026-10-19) | exec command rules and an exec gate: the new image's argument area against the pin's MAC; a differing or unreadable one is killed (`argv-changed`, `argv-unreadable`) | P2 |
| `path_rename`, `path_link` | REFER: refused when the source's nearest entry is stricter than the destination's. Stops a `deny_read` file moving out of its tree. | A |
| `path_unlink`, `path_rmdir` | write entries; `deny_write` targets **and their ancestors up to the write entry** (supervisor.md R15c ancestor rows). | A |
| `path_mknod` (in may_o_create), `path_mkdir`, `path_symlink`, `path_truncate`, `file_truncate` (where present) | write entries; a create under `deny_read`/`deny_write` | B |
| `path_chmod`, `path_chown`, `inode_setxattr/removexattr`, `inode_set_acl/remove_acl` (6.2+) | `deny_write` protection only (Landlock has none). The d_parent walk stays inside the superblock, with a row on each mounted root below a deny target. | B |
| `socket_create` | ADR 0018's family allowlist (kern≠0 returns 0) | B |
| `mmap_file`, `file_mprotect` | ADR 0027 exec-map (anonymous and write-tree PROT_EXEC) | C |
| `socket_connect`, `socket_sendmsg` on AF_UNIX, the LSM hooks over `unix_stream_connect` and `unix_may_send`; loaded only where `connect_unix` is absent (below 6.7) | `unix:` entries below 6.7 (no connect_unix) | D |

## 3. Decisions in the kernel

**Object.** `bpf/decide.bpf.c` is one CO-RE object with each body written once. Two macros emit `SEC("lsm/<hook>")` and `SEC("fmod_ret/security_<hook>")`. In fmod_ret mode each body first reproduces the wrapper's own early exits (IS_PRIVATE and `mmap_prot()`, ADR 0024 (8)). A source test enforces "0 or -EACCES only".

**Maps, all reused from tier 2 except the rows**
- `tego_run_set` (cgroup id → `tego_run{run_idx, gen, …}`). One lookup per hook; a miss returns 0 (I1). The row is armed after the stage's first execve and before the ack (ADR 0021 (2)), so the tego binary's exec is never decided.
- **New: `tego_plane_rows`**, a HASH_OF_MAPS with TEGO_MAX_SLOTS entries keyed by `run_idx`. The inner map is a HASH (NO_PREALLOC) keyed by `struct inode *`, with value `{kind, rule_idx, i_ino, i_generation, s_dev, gen}`. Exec rows carry `{parent inode*, name[≤255]}` in a second inner map (exec rows) of the same slot (ADR 0025 (1)).
- **New: `tego_plane_scratch`**, a TASK_STORAGE map holding the last decision `{rule_idx, hook, verdict}` for the recorder's fexit (ADR 0024 (11)).
- Rings: the plane's own refusal samples go to `tego_events[run_idx]`, stamped with `gen`.

**Path matching: inode keys plus a bounded (mount, dentry) walk.** Nearest entry wins (SEMANTICS §2).
- Rows are keyed by the inode pointer that the run's own Landlock domain pins (ADR 0025 (3): one neutral rule per keyed inode, which grants nothing new).
- The walk goes from the resolved dentry through d_parent, crossing to `mnt_parent`/`mnt_mountpoint` at a mount root. It is bounded to 64 steps, a mount crossing counts none (ADR 0024's walk-review note), and each step does one lookup in the slot's inner map.
- A disconnected root or an exhausted bound refuses with `path-unresolved`.
- On every hit, i_ino, i_generation and s_dev are compared with the row (and gen with the run). A mismatch refuses and bumps a counter.
- No strings or `bpf_d_path` (unavailable to `path_*` below 6.8).
- Rows are filled in the kernel by `bpf/decide_fill.bpf.c` (iter/task_file over the launcher's held O_PATH descriptors, task-scoped on 6.1+). Prepare checks the result against the `mnt_id`/`ino` it read when it planned (one statx per descriptor) and fails on a mismatch. Userspace never sees a key.

**Verifier plan**
- The walk is one **global subprogram**, verified once and called up to twice per program (rename and link walk both ends).
- Decided by T0 (ADR 0024 (1), (9)): before 6.8 (`__arg_trusted`) a global function cannot take a trusted BTF pointer, so the walk takes `u64` addresses through a per-CPU slot, and its body is `bpf_loop(64, step)` (form d: 391–896 instructions, ≤6 ms per program). It reads through `bpf_rdonly_cast` where BTF has the kfunc, else CO-RE probe reads: two object builds, picked by the probe. `bpf_loop` in BTF (5.17+ or a backport) is required. An lsm program maps the walk's int to 0/-EACCES.

**Per-run cost trap (decided, ADR 0025 (1) as amended 2026-09-29; T0 measured 11.8–79.8 ms a run for a new inner map against 0.00 ms for a new gen).** ADR 0026's amendment measured each HASH_OF_MAPS insert/delete waiting an RCU grace period (11.5/7.6 ms). ADR 0025 creates and drops an inner rows map per run: about 19 ms more on kill test 4 go's thin margin. Amend 0025: a slot keeps its row maps like its rings, cleared off the run's path. Every row carries `gen`; a stale row counts as absent and the walk continues past it. That is exact, since the current run's rows all exist before arming. Gen plus identity checks catch a recycled inode pointer. Slot reuse then needs "gen differs" rather than "inner map deleted" (ADR 0026 (6)).

## 4. Composition with tiers 1 and 2

- **Kept**
  - Tier 1's Landlock domain and seccomp filter, installed by the stage at every tier. The effective rule is the plane's walk ∩ Landlock (ADR 0024 (4)). The filter still refuses bpf(2), module loading and kexec (ADR 0033), relays connects, and notifies for the record until step E.
  - Tier 2: run cgroup, network programs, cgroup_track, per-run rings, reaper, linger, sweep, pinned builds.
- **Replaced**
  - fanotify: no marks when a plane mode is selected, removing the 21–25 µs open round trip, E15/E16/E34/E35/E37/E39/E40 and the static non-PIE requirement.
  - The supervisor's best-effort exec, deny_write and loader refusals (C30 a/b, C31, supervisor.md R15c), which the kernel now decides race-free.
  - At step E: the write-open and fs-mutation notifications (item 14).
- **Recorder**
  - ADR 0016's fexit on `security_file_open`/`path_*` reads the chain return and the plane's `rule_idx` from task storage. The plane emits its own sample only on hooks without a recorder fexit, so there is at most one verdict line per action. Built 2026-09-30 (T9b): a hook whose fexit the build did not attach counts as one without, by the build's `tego_plane_recorded` mask.
  - Built 2026-09-29 (ADR 0016 step 2): the ten fexit programs and the chain return in every fs record, and `tego_task_scratch`, the task storage the plane's `rule_idx` joins (T9).
  - Built 2026-09-29 (T9, enforce-plane §2.8): the plane's decision lives in its own task storage, `tego_plane_scratch`, which the recorder's object declares and pins beside it; each fexit takes the decision for its own call by hook and object. With the plane deciding execs, a continued exec's line is the kernel's (supervisor R7a amended).
- **Lifetime**
  - Programs are pinned under `/sys/fs/bpf/tego/<hash>-<mode>/` and adopted; linger (ADR 0022) keeps the up-to-2.3 s attach and removal off the run's path.

## 5. Ledger, verdict parity, compile --test

- A refusal line carries `mechanism: plane`, `decision_plane: lsm|fmod_ret` (no plane fields on fanotify), the rule ID from `rule_idx` (ADR 0030) and a reason (`denied-read`, `exec-not-allowed`, `refer`, `deny-write-ancestor`, `path-unresolved`). *Built at T9 (enforce-plane §2.8):* the reason stays in the closed set (`read-denied`, `exec-not-allowed`, the `*-outside-contract` codes, `path-unresolved`), since a v1 reader validates it, and the plane's `refer`, `deny-write-ancestor` and `identity-mismatch` are the additive `plane_reason`.
- The row compiler (ADR 0028 S4) and `compile --test`'s bpflsm column both come from `internal/policy/decide`'s **root model**. So Evaluate at bpflsm equals the rows by construction; ADR 0017 checks both against the kernel.
- Tier cgroup (plane) and bpflsm get one column. They split into mode columns only if a conformance cell differs (ADR 0019 condition). The fanotify column goes with 0028 S3.
- CAPABILITIES.md and `pkg/spec/backend/matrix.go` land as one golden pair (decision_plane, deny_read nested in write).

## 6. Doctor and tier selection

- D6 unchanged (LSM list plus root counting probe). D7's six `lsm/*` rows become one row per decide.bpf.c hook per mode, with BTF presence and 6.1 prototype arity.
- New plane mode probe (ADR 0024 (3)): load the mode's full set; per hook, one syscall refused inside a scratch cgroup and passing outside it; lockdown (confidentiality: the rdonly build only; no mode without `bpf_rdonly_cast`), `bpf_loop`/`bpf_rdonly_cast` in BTF (object build) and CONFIG_LTO_CLANG (no fmod_ret) checks. Cached per boot+build in runcache.go and in the pin directory, so an adopting run probes nothing.
- Selection: `bpflsm` needs LSM mode; `cgroup` takes the best of lsm, fmod_ret, fanotify; `auto` prefers bpflsm; `bpf.plane: auto|lsm|fmod_ret` is /etc-only. A pinned `--tier bpflsm` without LSM mode refuses at Prepare with doctor's GRUB fix, never a silent fallback.

## 7. Kernel matrix and fallbacks

| Row | bpf LSM | bpflsm | tier cgroup mode | Notes |
|---|---|---|---|---|
| RHEL 9 5.14 | yes | yes | lsm | no task-scoped iter (unscoped fill, measure); backported `bpf_loop` and `bpf_rdonly_cast`: rdonly build, also under confidentiality |
| AL2023 6.1 | yes | yes | lsm | no `file_truncate`; cold removal about 3.7 s (linger); no `bpf_rdonly_cast`: probe-read build |
| Ubuntu 24.04 6.8 / 25.10 6.17 / development machine 6.17 | no | after GRUB drop-in | fmod_ret | KVM: `TEGO_VM_LSM=…,bpf` for LSM mode; Ubuntu 25.10's matrix row reads fmod_ret, then lsm on its second boot (2026-10-05) |
| Debian 13 / RHEL 10 6.12, Fedora 7.0 and 7.2 | yes | yes | lsm | Fedora 7.2 (Landlock ABI 10) measured 2026-10-05 |
| Ubuntu 22.04 5.15 | no | no tier | none | Landlock ABI 1: doctor offers no tier, so no plane is selected; a doctor-only matrix row (2026-10-05) |
| lockdown=confidentiality without `bpf_rdonly_cast` in BTF (AL2023 6.1) | – | no | fanotify | probe reads refused at load on every kernel (T0), so only the rdonly build loads under confidentiality |
| no `bpf_loop` in BTF (below 5.17, no backport) | – | no | fanotify | |
| arm64 | ? | probe decides | expect fanotify | no guest row; since 2026-10-06 ci.yml's `build-test-arm64` runs the plane's tests as root on the hosted runner (enforce-plane R28), result not yet recorded |

## 8. Security argument

- **Fail-closed.** The plane only refuses: over-admitting falls to the Landlock floor, over-refusing fails closed. An unresolved walk, an identity mismatch or a missing row map under a live run-set row refuses. A mode failing any hook is never selected; a pinned tier then refuses the run.
- **TOCTOU.** Decisions are on bprm->file, the opened file and the path hook's locked dentry. The remaining race, an ancestor renamed during the unlocked d_parent walk, cannot loosen a rule because REFER and ancestor rows refuse loosening moves. Step B's symlink-swap and rename-race cells test it.
- **Launcher death** changes nothing: pins, domain-held inodes and the reaper (ADR 0020).
- **Scope and root visibility.** Cgroup-scoped, named and pinned in tego's bpffs directory, listed by doctor, removed by gc. The agent cannot reach bpf(2) (ADR 0033).
- **Residuals:** fmod_ret skips other LSMs on a refusal; an unmount after launcher and reaper both die (0025 (5)); an SCM_RIGHTS descriptor from outside the run is not re-decided (no `file_permission`); root can read inode addresses from the maps.

## 9. Test plan

- **Unit:** row compiler (nearest-wins, ancestor rows, exec parent+name, neutral rules keep the union); return discipline; gen encoding; select, Buildable and doctor derivation over fakes.
- **Verifier-load tests** (`-tags tegobpf`, root, in the KVM guest): both modes' full sets load and attach on every MATRIX row. Record instruction counts and load time, and fail over a budget.
- **KVM root suites** (`test/vm/kvm-run.sh`, `TEGO_VM_LSM=lockdown,capability,landlock,yama,bpf`, plus a default-lsm boot for fmod_ret):
  - every hook refuses in the run and allows outside it and in a second run;
  - REFER: rename or link of a deny_read file out of its tree is refused;
  - `mv .git .git.old` is refused;
  - a direct `ld.so` is refused, PT_INTERP loads, and memfd exec is refused;
  - a hard link under another name is refused;
  - SIGKILL of the launcher with drop_caches still refuses;
  - btrfs subvolumes and overlayfs;
  - lockdown=confidentiality boots; host opens unaffected.
- **Conformance** (ADR 0017): adds a mode axis (lsm, fmod_ret, fanotify) and checks that the ledger, `compile --test` and the kernel agree per cell.
- **Performance budgets** (`make vm-perf`, `test/perf`, enforce-plane §10.1): warm start at bpflsm at most 1 s and at most 600 ms over tier landlock (target 130 ms, kill test 4's allowance), cold start at most 9 s (target 2.3 s), Prepare's fill at 1000 rows at most 1 s, open cost over landlock at most 2 us, and the plane's open cost at 2, 8 and 32 concurrent runs at most 1.5x landlock's. The suite fails over a limit and prints TARGET-MISS over a target. The numbers above are the suite's limits and targets as `test/perf` enforces them.
- **Kill tests 1, 4 and 7 at bpflsm** on the guest and MATRIX. Kill test 4 go must pass 19/20 within 2× bare: at most about one baseline (117–129 ms) of excess, with open cost ≤2 µs in the 20,000-open loop. `tier2-pairs.sh` runs 1,000 pairs with no stall. *Measured 2026-09-30 (enforce-plane §2.18):* go passes on 6.17 at `cgroup` (142 / 216 ms, 1.52x) and `bpflsm` (138 / 218 ms, 1.58x) on a quiet host, from 315 and 485 ms, once later runs adopt the pinned plane, parse no BTF and, below 6.7, read the map-of-maps outers without a grace period each (AL2023 6.1: 1.54-1.64x at load 6-9). The open budget is not met: 2.1-2.9 µs over bare is the Landlock floor and the recorder's read record before the plane's 0.3-0.8 µs (§2.18's condition 1).
- **Which record mode the 2 µs covers.** The budget is the plane's decision cost per open under `record: summary`, the mode kill test 4 runs (`test/e2e/kt4-ordinary.sh`) and the default: the plane's lookup and walk plus the recorder's fexit sample for an open, with no body captured.
- **`record: full` costs more, on its own line.** The recorder's cost with `record: full` was 65–110 µs an open in a review of 2026-09-30, and the 2 µs budget does not cover it. It is the recorder's, not the plane's; it is not re-measured here, and kill test 4 does not run it.

## 10. Tickets

When this plan was written none of its prerequisites was built. They are built as of 2026-09-30: 0017 v1, 0028 S1 and S4 (the decide core and `CompilePlane`; the Prepare-time plan and the 1 µs gate stay open), 0021 (arming and `proc.Start`), 0020 (the reaper) and 0016 steps 1 to 3. T0 to T11, T9b and T13 to T15 are built (their rows say when). T16's filesystem and exec handovers are built as of 2026-10-04, gated on actual kernel decision and outcome-recording coverage (§2.19 of enforce-plane.md). The table retains dated acceptance results; implementation status does not turn historical measurements into acceptance of a newer executable.

| # | Ticket | Files | Deps | Acceptance |
|---|---|---|---|---|
| T0 | Spike (S): global-walk argument typing, walk load time per hook on 5.14/6.1/6.17, both modes; cost of a rows-map insert vs clear-and-reuse. **Done 2026-09-29.** | scratch only, results into ADR 0024/0025 | – | numbers per row; walk form chosen |
| T1 | ADRs (S): accept 0017, 0020, 0024, 0025, 0027, 0028; amend 0025 (slot row-map reuse with gen); amend 0019 (one plane column). **Done 2026-09-29 (§11).** | docs/adr | T0 | reviewed, Status accepted |
| T2 | Maps and skeleton (S): `tego_plane_rows`, exec rows, task-storage scratch, a counters array; decide.bpf.c with the dual-SEC macro; gen.go line; `bpf/tests` return-discipline and dual-SEC coverage tests. **Done 2026-09-29.** | bpf/include/maps.h, bpf/decide.bpf.c, internal/bpf/gen.go, objects*.go, bpf/tests | T0 | objects generate; source tests pass |
| T3 | Step A hooks (L): walk subprogram; file_open, bprm_check, path_rename/link (REFER), unlink/rmdir with ancestor rows. **Done 2026-09-29** (`TestPlaneStepAHooksDecide`). | bpf/decide.bpf.c | T2 | load test on all rows; guest cells for step A |
| T4 | Fill (M): decide_fill.bpf.c iter/task_file, Go fill, fdinfo verification. **Done 2026-09-29** (enforce-plane §2.6). *2026-10-05:* the 0023 dependency was not met (ADR 0024's correction note): the fill rests on enforce-plane R16's check alone until ADR 0023 C11b leases the held descriptors across the iterator | bpf/decide_fill.bpf.c, enforce/cgroup/planefill.go | T2, 0023 | a reused descriptor number fails Prepare; unscoped fill measured on 5.14 |
| T5 | Row compiler (M): 0028 S4 root-model rows, NeutralRule in the Landlock plan, keyed-inode cap reported by compile. **Done 2026-09-29** (`decide.CompilePlane`; enforce-plane §2.4) | internal/policy/decide | 0028 S1 | union-unchanged property test; zero allocations |
| T6 | Plane backend (L): mode load and adopt (`<hash>-<mode>` pins), per-slot row maps with gen reuse, Arm after the stage exec, purge in Detach/purgeSlot/reaper, no fanotify marks when a plane is selected. **Done 2026-09-29** (enforce-plane §2.8) | enforce/cgroup/plane.go, slots.go, attach.go, internal/runtime/run.go | T3–T5, 0020, 0021 | launcher SIGKILL cell; slot-reuse stale-row cell; 2/8/32 concurrent runs |
| T7 | Tier wiring (S): bpflsm package as a constructor requiring LSM mode over the cgroup backend; Buildable; select; `bpf.plane` config. **Done 2026-09-29** (enforce-plane §2.10; `bpf.plane` was T8's) | enforce/bpflsm, enforce/buildable.go, select.go, spec/config/v0 | T6 | `--tier bpflsm` runs in an lsm=bpf guest and refuses with the GRUB fix without it |
| T8 | Doctor plane probe (M): D7 rows per hook and mode, scoped per-hook refusal probe, lockdown/LTO/prototype checks, runcache and mode file. **Built 2026-09-29** (enforce-plane §2.6; T6/T7 read `Report.PlaneFor` and write the pin with `PinPlaneAnswer`). | internal/doctor/plane.go, programs.go, derive.go, runcache.go | T3 (stub object early) | doctor golden on both boots; adopting run probes nothing |
| T9 | Record (M): rule_idx in task storage; the plane's own samples on bprm_check; ledger mechanism, reason and rule. **Built 2026-09-29** (enforce-plane §2.8; T6's handle implements `enforce.DecisionPlaneReporter`) | bpf/decide.bpf.c, observe, internal/runtime | T3, 0016 s2–3 | one verdict line per action (0017 (a)) |
| T10 | compile --test / capabilities (S): bpflsm column from the core; CAPABILITIES and matrix.go golden pair. **Done 2026-09-29;** `decide.PlaneEvaluator`, `TestCompileTestBPFLSMColumnGolden`, `TestMatrixGolden`, conformance bpflsm expectations; the kernel-side parity cells wait for T6/T11**).** | internal/cli, pkg/spec/backend, spec/backend | T5 | parity on 0017 cells |
| T11 | Suites and kill tests (M): the lsm=bpf and default-lsm guest jobs in root-suites.sh and matrix.sh; conformance mode axis; kill tests 1/4/7 at bpflsm | test/vm, test/conformance | T6–T10 | §9 green on GUEST and MATRIX. **Done 2026-09-30** (enforce-plane §2.18; results in test/vm/README.md): the jobs, the axis, the parity cells and the kill tests are built and run on the 6.17 guest (both boots), debian-13, rhel-9 and al2023; §9 is not all green: kill tests 1 and 4 (pip) at bpflsm are refused on the guest's uutils userland (exec rows keyed by (inode, name) needed) and kill test 4's go kind misses 2x at tiers cgroup and bpflsm (a root run's fixed cost), §2.18's conditions. |
| T12 | Docs (S, parallel): docs/p0/enforce-plane.md (PLN-*), ARCHITECTURE §2/§10/§11/§14 (§10's inode-storage text superseded), FEATURES E8/E9b/E54, SEMANTICS §2/§4/§5, GAPS B1/B6/C30–32 | docs | T1 | rulecheck clean. **Status pass 2026-09-29:** rules, invariants and cases carry built state and their building ticket; the other docs' notes say what is built; the ledger of unbuilt work is T7, T11, T13-T16. |
| T13 | Step B (M): mknod, mkdir, symlink, truncate, chmod/chown/xattr/ACL with mounted-root rows; socket_create plus io_uring. **Done 2026-09-29** (enforce-plane §2.12: the bodies in `bpf/decide_stepb.h`, the overlay copy-up condition settled, `io_uring: true` admitted with a plane mode) | decide.bpf.c, plane rows | T6 | no file left by a refused create; TOCTOU cells; setfacl refused |
| T14 | Step C (M): ADR 0027 mmap_file/file_mprotect, then the memfd seccomp arm dropped. **Built 2026-09-30** (enforce-plane §2.14; the hooks in `bpf/decide_stepc.h`, the arm dropped through `landlock.Run.PlaneMaps`; four conditions) | decide.bpf.c, landlock filter | T13 | exec-map cells; memfd arm drop gated on the probe |
| T15 | Step D (S): unix hooks below 6.7. **Built 2026-09-29** (enforce-plane §2.11): `socket_connect`/`socket_sendmsg` on AF_UNIX, keyed by the socket's cgroup, loaded where `connect_unix` is absent | decide.bpf.c, enforce/cgroup plane.go | T6 | cells on 5.14/6.1 |
| T16 | Step E (S): the filter stops notifying write-opens and mutations, and the supervisor stops its best-effort exec, `deny_write` and loader refusals where a plane mode decides them (enforce-plane R22, supervisor half). **Mechanism built 2026-09-30** (enforce-plane §2.13): per loaded hook, gated on a recorder that names path hooks by path; **fs half enabled 2026-09-30** (§2.15: the recorder walks each parent directory in the kernel); the exec hand-over waits for a named kernel exec line. **Exec half built 2026-10-04** (enforce-plane §2.19): exec notifications keep capturing metadata, while a ready recorder and both pinned failure-result hooks delegate policy and terminal outcomes to the kernel; missing coverage keeps supervisor enforcement. | enforce/landlock filter, supervisor, observe, trace_proc | T13, T9 | kill test 4 pip timing. *Amended 2026-10-05:* the fs half's kill test 4 pip timing is recorded (enforce-plane §2.13, §2.15); kill test 4 has not been re-run on the exec hand-over build, so that acceptance is open for it. The exec half's correctness tests are `TestPlaneRunExecOutcomes` and `TestPlaneRunExecEntryPrecedence` (2026-10-04, integration, root). |
| T9b | Record fallback (S): a fexit recorder that cannot attach leaves the plane's own sample on every step A hook, not only `bprm_check` (enforce-plane §7, R23). **Built 2026-09-30** (enforce-plane §2.17: the build's `tego_plane_recorded` mask, `TEGO_EV_PLANE_FS` on every step A and step B hook a fexit wraps) | bpf/decide.bpf.c, observe | T9, T13 | one line per action with the recorder detached |

**Parallelism.**
- After T0/T1, T2, T5, T8 (against a stub), T10 and T12 run concurrently.
- T3 and T4 split after T2. T6 is the join.
- T13–T15 each touch separate hook bodies and can run in parallel once T6 lands.
- One agent owns decide.bpf.c's macro and header; others add hook bodies in `decide_<group>.h` includes.

## 11. ADRs first

Done 2026-09-29 (T0, then T1):

1. **Accepted 0024 and 0025, as amended by T0.** 0024 (1) names the walk's form: one global subprogram whose body is `bpf_loop(64, step)` (391–896 verified instructions per program, ≤6 ms per lsm program, against 16k–573k and up to 0.8 s for a plain loop); an lsm program maps the walk's int to 0/-EACCES; `bpf_loop` in BTF (5.17+ or a backport) is a condition of any plane mode. 0024 (9): two object builds, `bpf_rdonly_cast` reads where BTF has the kfunc, probe reads otherwise, picked by the probe; lockdown=confidentiality refuses probe reads on every kernel, 6.17 included, so under it only the rdonly build loads (6.17, RHEL 9.8) and AL2023 6.1 has no plane mode. fmod_ret needs no LTO exclusion on any measured row. 0025 (1): a slot keeps its row maps, rows carry gen, a stale row is absent, and the clear runs in the kernel off the run's path (0.00 ms a run against 11.8–79.8 ms for a new inner map). 0026 (6) is amended by a dated note to match.
2. **0019 amended:** tier cgroup with a plane and tier bpflsm share one `compile --test` column, split only when an ADR 0017 cell differs.
3. **Prerequisites.** 0028 accepted (S1 built in part in `internal/policy/decide`; the Prepare-time plan and the 1 µs gate are still open). 0017 accepted, v1 built. 0020 and 0021 accepted, implementation in progress; 0020 (3) now leaves row maps and rings to the slot. 0016 accepted, step 1 built, steps 2–3 in progress.
4. **0027 accepted** before T14, with one correction: `file_mprotect` decides on the effective prot (the hook's `prot`), not `reqprot`, which let a READ_IMPLIES_EXEC mprotect map written code executable.
5. No new ADR: T0 settled the walk's form inside 0024.
