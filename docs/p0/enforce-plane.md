# Tier 3 and the kernel decision plane — `bpf/decide.bpf.c`, `enforce/cgroup` plane, `enforce/bpflsm` (P0 detailed spec)

Written 2026-09-29 from ADRs 0024, 0025, 0026, 0027 and 0028 and `docs/p0/TIER3-PLAN.md` (ticket T12); status brought
to the tree of 2026-09-29, updated through T16 on 2026-10-04. **Steps A to E are built and run in tier cgroup's backend and as tier `bpflsm`; step E's
filesystem handover is enabled (§2.15) and its exec handover is gated on complete live kernel recording (§2.19).** Built: T2 (skeleton, §2.3), T5 (row compiler, §2.4), T8 (doctor's probe and selection,
§2.5), T4 (fill, §2.6), T3 (Step A's six bodies, §2.7), T9 (the record, §2.8), T6 (the plane in tier cgroup, §2.9) and
T10 (`compile --test`'s `bpflsm` column, R25), T7 (tier `bpflsm`, §2.10), T15 (Step D, §2.11), T13 (Step B, §2.12)
and T14 (Step C, §2.14), T16 (step E, §2.13, §2.15). A rule leaves "not built yet" only in the change that builds it and
gives it a test; its title says which half is built when only one is, and `tools/rulecheck` fails a cited test no
function declares (`-strict` counts the rules no test names). T11 (guest suites, conformance mode axis, kill tests and kernel-side parity cells) is built; its dated
acceptance results are in TIER3-PLAN §10. T16 delegates filesystem and exec decisions
where the required hooks and recorder are active; missing exec outcome coverage retains supervisor ownership. The ADRs are accepted (TIER3-PLAN T1,
§11), 0024 and 0025 as amended by T0; where this document and an ADR differ, the ADR text is the decision.

Rule IDs here are the tool's bare form (`R1`, `E1`, `I1`): `tools/rulecheck` reads only R/E/I IDs, the ADR 0030
prefix rename is not done, and a rule of this document is named from another as `enforce-plane R5`. The plan's
`PLN-*` name maps onto them one to one when the rename lands.

## 1. Purpose and boundaries

**Owns.** The decision plane: the one CO-RE object `bpf/decide.bpf.c` (and `bpf/decide_fill.bpf.c`), its maps, its
two attach modes (LSM, `fmod_ret`), the row layout, the ancestry walk, the fill, arming, mode probe and selection,
the tier `bpflsm` constructor over the tier-2 backend, the plane's ledger lines and the plane's column in
`compile --test`. It decides, per governed run and in the kernel, opens, execs and fs mutations on the object the
kernel resolved.

*Amended 2026-10-16 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) D2, Stage B):* the run's open deputy (`gate.completion: held`) is a process of
the run cgroup, so the plane decides its opens as it decides the agent's: a held open is never more permissive than
the agent's own in what the plane decides. Two residuals outside the plane are named in ADR 0041's review note: D2's
LSM label check is not built (the deputy's open is made under its own AppArmor or SELinux label), and an `O_CREAT`
reopen of an existing file in a sticky directory skips `fs.protected_regular`. It needs no plane exec row, which ADR 0041 D2 foresaw: its exec completes before the stage reports, so
before Arm places the run's row, as the stage's own exec of tego does.

**Non-goals** (the 2026-09-23 scope, TIER3-PLAN §1).
- No host-wide control: a program returns 0 unless `bpf_get_current_cgroup_id()` hits `tego_run_set`.
- No resistance to root: root can list (`bpftool prog`, doctor) and remove (`tego gc --builds`, unpin) every
  program. No kernel module. No model-based judging (ADR 0003).
- No LSM hook decides an inet destination or an inet bind: no `socket_connect` or `socket_sendmsg` for inet
  families and no `socket_bind` for them, which would double-decide what the per-run cgroup programs already decide
  (FEATURES E54). The plane's socket hooks are `socket_create` (step B, ADR 0018's family allowlist, §2.1 and §2.12);
  below 6.7, where `cgroup/connect_unix` is absent, `socket_connect` and `socket_sendmsg` for AF_UNIX names (step D,
  §2.11); and, where the contract declares `net.listen`, `socket_bind` for AF_UNIX addresses and `socket_listen` for
  AF_UNIX and inet TCP sockets (§2.20). All of them are decision code under R1 to R3. *Amended 2026-10-05:* this
  bullet said the plane had no LSM network hooks at all, which `socket_create`, step D and the listener hooks
  contradicted.
- No `file_permission` (a stated residual) and no `task_kill` (Landlock ABI 6 scopes signals). *Amended 2026-10-05:*
  `ptrace_access_check`, `ptrace_traceme`, `bpf` and `key_permission` are built on the same plane (§2.20); this bullet
  said they stayed FEATURES E54, P1.
- Not owned: the cgroup network programs, recorder and rings (enforce-cgroup-observe), Landlock (enforce-landlock),
  the seccomp filter (supervisor), the row model (`internal/policy/decide`, ADR 0028), lifetime (ADR 0020, 0022).

## 2. Hooks and rows

### 2.1 Hook to contract-rule map (ADR 0024 (5); landing order A to D)

| Hook | Contract rule | Step |
|---|---|---|
| `file_open` | fs `deny_read` (read), write/ask/`deny_write` for write-opens and `O_TRUNC`; never exec rows; skips a file on a private clone, FMODE_BACKING (6.6+) opens included | A |
| `bprm_check_security` | `exec.allow` by inode, parent-dir inode and name bytes; `exec.anonymous`; a directly invoked loader; a `#!` stage passes | A |
| `path_rename`, `path_link` | REFER: refused when the source's nearest entry is stricter than the destination's | A |
| `path_unlink`, `path_rmdir` | write entries; `deny_write` targets and their ancestors up to the write entry | A |
| `path_mknod`, `path_mkdir`, `path_symlink`, `path_truncate`, `file_truncate` (where present) | write entries; a create under `deny_read`/`deny_write` | B |
| `path_chmod`, `path_chown`, `inode_setxattr`, `inode_removexattr`, `inode_set_acl`, `inode_remove_acl` (6.2+) | `deny_write` protection only | B |
| `socket_create` | ADR 0018's family allowlist under a `net:` section (io_uring's `IORING_OP_SOCKET` included); `kern != 0` returns 0 | B |
| `mmap_file`, `file_mprotect` | ADR 0027's exec-map policy | C |
| `socket_connect`, `socket_sendmsg` (AF_UNIX; loaded only where `cgroup/connect_unix` is absent) | `unix:` entries below 6.7 (§2.11; ADR 0024 named `unix_stream_connect`, `unix_may_send`) | D |
| `socket_bind` (AF_UNIX addresses; any other family returns 0) | `net.listen`'s `unix:` entries: an abstract name here, a pathname at `path_mknod` against its resolved parent; autobind refused | E54 (§2.20) |
| `unix_may_send` (every kernel with a plane) | ADR 0113 immutable IPC floor on the actual bound datagram peer; peer/name and inode checks, including connected sends and aliases | C40 |
| `socket_listen` | `net.listen`: a Unix socket's bound name; an inet TCP socket's bound address against the cgroup bind table | E54 (§2.20) |
| `ptrace_access_check` (ATTACH mode), `ptrace_traceme` | the run-tree process boundary (FEATURES E8): the peer must be in the same run and gen | E54 (§2.20) |
| `bpf` | every `bpf(2)` command of a governed task is refused | E54 (§2.20) |
| `key_permission` (where present) | `keyring: true`; without it every key permission check is refused | E54 (§2.20) |
| `capable` (mandatory) | refuse CAP_SYS_ADMIN in every user namespace, holding mount topology for adopted tasks too; no contract opt-out | ADR 0055 NET09 |

### 2.2 Maps (all reused from tier 2 except the rows)

| Map | Type and key | Value | Purpose |
|---|---|---|---|
| `tego_run_set` | hash, cgroup id | `tego_run{run_idx, gen, ...}` | the scope; one lookup per hook; a miss returns 0 |
| `tego_plane_rows` (new) | HASH_OF_MAPS, `run_idx`, TEGO_MAX_SLOTS entries | inner HASH (NO_PREALLOC, 4096) | one inner map per slot, kept across runs |
| inner rows map | `struct inode *` | `tego_plane_row{i_ino, i_generation, s_dev, gen, rule_idx, kind}` | fs rows; `kind` and `rule_idx` as §2.4 |
| `tego_plane_exec_rows` (new) | HASH_OF_MAPS, `run_idx`; inner HASH (NO_PREALLOC, 1024) keyed by a link key (the executable's `struct inode *`, its directory's and its name) or a name key | `tego_plane_exec_row{parent inode *, parent_ino, parent_generation, i_ino, i_generation, s_dev, gen, rule_idx, name_len, flags, name[256]}` | exec rows of the same slot |
| `tego_plane_scratch` (new) | TASK_STORAGE | `tego_plane_decision{rule_idx, hook, verdict, reason, launder_dentry, launder_mnt}` | the last decision, for the recorder's fexit; the walk's laundered pointers |
| `tego_plane_slots` (new) | ARRAY, `run_idx` | `tego_plane_slot{gen, flags, fs_rows, exec_rows}` | the slot's header: the gen of the run its rows are for and what that run decides (exec, exec.anonymous, unix, net, ICMP); written last by Prepare, zeroed first by every clear; a header of another gen refuses every decided hook (R6) |
| `tego_events[run_idx]` | ring, existing (ADR 0026) | | the plane's own refusal samples, stamped with `gen` |
| `tego_plane_counters` (new) | ARRAY, `run_idx` | `tego_plane_counts{mismatch, unresolved, bound, norows}` | fail-closed outcomes per slot, zeroed at Prepare; a stale row walked past is not counted (R6); `norows` also counts a slot with no header of the run's gen |
| `tego_plane_unix_policy` (new, T15) | ARRAY, `run_idx` | `tego_plane_unix{relay_cgroup_id, gen, decides, zero}` | step D's per-slot policy, written with the run's gen by the fill; none of the run's gen refuses (§2.11) |
| `tego_plane_recorded` (new, T9b) | ARRAY, one entry (key 0), pinned in the mode's directory | `__u32` mask of `1 << enum tego_plane_hook` | the build's attached recorder fexit programs; a refusal on a hook whose bit is clear writes the plane's own sample (§2.17); 0, the value nobody wrote, samples every refusal |
| `tego_unix_names` | LPM trie, existing (enforce-cgroup-observe §5 R7) | `tego_net_verdict` | the run's unix: and fs name rows, read by step D below 6.7 as by `connect_unix` on 6.7+ |
| `tego_plane_listen_rows` (new, §2.20) | HASH_OF_MAPS, `run_idx`; inner HASH (256 rows) keyed by `tego_plane_listen_key{parent inode *, name_len, abstract, name[108]}` | `tego_plane_listen_row{parent_ino, parent_generation, s_dev, gen, rule_idx}` | the declared Unix listeners of the slot, filled and cleared with the fs and exec rows (`TEGO_PLANE_FILL_MAX` counts them); a row of another gen is absent |
| `tego_net_control`, `tego_bind_exact`, `tego_net_binds` | hash, existing (network-controls) | | `socket_listen`'s inet admission reads the run's cgroup bind table; the plane writes none of them |

*Amended 2026-10-05:* the slot header's flags also carry `TEGO_SLOT_LISTEN_DECIDES` (the contract declares
`net.listen`: `socket_bind` and `socket_listen` decide) and `TEGO_SLOT_KEYRING_ALLOWED` (`keyring: true`), and the
task scratch carries the listener marker (`listen_sock`, `listen_run_idx`, `listen_gen` and the `bind` result block)
that the terminal bind/listen producers read and clear (§2.20).

### 2.3 Built at T2 (skeleton; no rule above is built by it)

At T2 (TIER3-PLAN) the object, the maps and the walk went into the tree with each hook body a stub that looked its run
up and returned 0; T3 wrote the decisions and T6 loads them for a run. What T2 added:

- `bpf/decide.bpf.c`: the `TEGO_PLANE_HOOK(name, lsm_hook, security_fn, (params), (args)) { body }` macro emits
  `tego_lsm_<name>` (SEC `lsm/<lsm_hook>`) and `tego_fmr_<name>` (SEC `fmod_ret/<security_fn>`) around one
  body, both returning `tego_plane_verdict(body)`, which is `0` or `-EACCES` (R2, R4). The body gets the mode as a
  constant for fmod_ret's early exits. Step A's six hooks; `internal/bpf.PlaneHooks` names them.
- The walk, `tego_plane_walk(u64 dentry, u64 vfsmount, u32 run_idx, u32 gen, struct tego_plane_hit *)`: ADR
  0024's T0 form d (global subprogram, `bpf_loop(64, step)`), returning `enum tego_plane_walk_result`
  (ROOT, HIT, and the fail-closed UNRESOLVED, BOUND, MISMATCH, NOROWS, each counted at the slot); a row of another
  `gen` is walked past (R6, R7). `file_open`'s stub calls it and discards the answer, only so the verifier checks it.
- Two builds (`internal/bpf/gen.go`): `decide_rd` reads through `bpf_rdonly_cast`, `decide_pr` through CO-RE probe
  reads; the probe (T8) picks one from BTF and lockdown. They are registered apart from the tier-2 objects
  (`bpf.PlaneObjects`); `bpf.Hash` covers both.
- Two departures from the table's first draft, decided here. The walk's pointers are laundered through the task's
  `tego_plane_scratch` value, not T0's per-CPU slot, which a preempted program shares with the next program on its
  CPU. Exec rows are keyed by the executable's inode pointer, with the parent and the name in the value: the lookup
  needs no key built from the name, which under lockdown=confidentiality no probe read could copy. How `bprm_check`
  compares the name without a string read (for instance the dentry's `d_name.hash_len`, which the fill reads from
  the same dentry) is T3's and T4's.
- Tests: `bpf/tests` `TestPlaneHooksHaveBothSections`, `TestPlaneReturnsOnlyZeroOrEACCES`,
  `TestPlaneWalkHasNoStringOps`; `internal/bpf` `TestPlaneObjectShape`, `TestPlaneLayoutParity`,
  `TestPlaneCORERelocationsResolve`, `TestPlaneAttachTargetsResolve`, and the root `TestPlaneLoadsAndAttaches` (both
  builds in each mode the kernel offers, verified instructions held to 20,000; 6.17 guest: `file_open` 720 (pr)
  and 2,880 (rd), the stubs 8).

### 2.4 Built at T5 (the row compiler, `internal/policy/decide` `planerows.go`)

`decide.CompilePlane(rt)` compiles a RuleTable into `PlaneRows`, keyed by canonical path; the fill (T4) opens each path
and keys its row by the inode. It is ADR 0028 S4, from the root model, so the rows and `compile --test`'s bpflsm column
cannot disagree (R25).

- **Complete rows.** The kernel's walk stops at the first row of the run's gen (§2.3); it does not go on past a row whose
  entry does not decide the question. So each row carries the root model's answer *at its own path* for every question,
  inherited from above where its own entries do not decide (a watch entry; an implicit entry for a read; a row that is
  not an entry). A path whose nearest row is p takes p's answer: every entry's path is a row, so no entry lies between.
- **Rows.** One per canonical path an fs entry names; each built-in `deny_write` target and every directory above it up
  to the outermost write entry enclosing it (R11); for a target declared through a symlink, that spelling and each
  directory above it up to the outermost write entry, keyed at their own inode (`PlaneRows.NoFollow`, R11); each
  `exec.allow` directory (its resolved path).
- **`kind`** (`decide.PlaneKind`, a `u8`): bit 0 `PlaneReadDeny` (a read here is refused), bit 1 `PlaneModifyAllow` (a
  modification here is allowed), bit 2 `PlaneRenameRefused` (renaming this inode itself, depth 0, is refused: a
  `deny_write` target or a directory above one), bit 3 `PlaneExecDir` (an `exec.allow` directory covers the inode). No
  bit set: reads allowed, modifications refused, which is also the answer of a walk that meets no row.
- **`rule_idx` is the row's position in `PlaneRows.FS`**, not an entry's. A row answers a read, a modification and a
  rename of itself, whose deciding entries can differ (a `deny_read` and an implicit entry at one path; a write entry at a
  `deny_read`'s path; a `deny_write` target, which is not in `RuleTable.FS`), and one `u16` cannot name them all. The
  ledger (T9) resolves a position by the hook's question: `PlaneRows.RuleAt(row, question, depth)`.
- **REFER strictness** (R10): `PlaneKind.Strictness` is 2 for `PlaneReadDeny`, 1 without `PlaneModifyAllow`, 0 with it;
  `PlaneReferRefused(src, dst)` refuses when the source's nearest row is stricter. In the root model both ends must
  allow the modification first, so both are 0 and the comparison never refuses on its own.
- **Exec rows**: one per exec file entry at its resolved spelling (the name `bprm->file`'s dentry carries), with the
  parent directory and final name; directories are fs rows with `PlaneExecDir`; entries written as a bare name
  (`ByName`) are `PlaneRows.Names` and key no inode (T3 keys them by `internal/bpf.PlaneNameKey` and compares the bytes, §2.7). An exec
  entry that does not allow (an ask entry, P1) has no row form and is `ErrPlaneExecVerdict`.
- **Keyed inodes and neutral rules** (R17): `PlaneRows.Keyed` is every fs row, executable and executable's directory.
  `PlaneRows.Neutral` pins each keyed inode where the domain already grants a read right, with that right: READ_FILE and
  READ_DIR only, never a write right, taken from the grants the builder certainly adds on the path or above it (write
  entries, exec entries, "/"'s read set or the enumeration's levels and siblings). The builder masks it by ABI and
  file-ness and adds nothing when that leaves nothing (a file under an enforced `deny_read`, where Landlock refuses every
  open itself; ADR 0025 (3)).
- **The cap** (E13): at most 4096 fs rows and 1024 exec rows a run, the slot maps' sizes; the exec map also holds,
  when the contract has an `exec:` section, a row per bare-name entry, which counts against its 1024
  (`PlaneRows.ExecMapEntries`), and the fs map holds the mount rows, which count against its 4096
  (`PlaneRows.FSMapEntries`) (`TEGO_PLANE_ROWS_MAX`,
  `TEGO_PLANE_EXEC_ROWS_MAX`, held equal by `internal/bpf` `TestPlaneCapsMatchRowCompiler`). **Decided: a table over
  the cap is a compile error when bpflsm is the only tier it can run at (pinned), and a warning naming bpflsm when an
  auto run may land there, which is then given tier cgroup (condition 7)** (`decide.PlaneDiagnostic`, called by
  `tego compile`), never an `[unenforced]` truncation: a row left out is a rule
  the kernel does not apply, and a quieter run is the silent fallback I7 forbids. The built-in `.env` scan can name up to
  50,000 files, so such a project runs at tier cgroup until the rows are widened (a row per directory rather than per
  file is a later change).
- **Tests**: `TestPlaneRowsMatchEvaluate` (every generated table, 1,000+, with and without `deny_write` targets; the
  kernel-order walk and `RootIndex.Walk` over the rows against Evaluate's bpflsm column, verdict, rule and reason, and
  every rename pair), `TestPlaneRowsDenyWriteAncestors`, `TestPlaneKindStrictness`, `TestPlaneExecMatchesMatchExec`,
  `TestNeutralRulesKeepTheUnion` (a Landlock plan model, itself held to Evaluate at landlock, whose grant at every probe,
  keyed path and path beneath one is unchanged by the neutral rules), `TestPlaneCap`, `TestPlaneDiagnostic`,
  `TestPlaneQueriesAllocateNothing`; benchmarks `BenchmarkPlaneDecide` (about 0.4 µs a question, 0 allocations),
  `BenchmarkPlaneExecMatch`, `BenchmarkCompilePlane` (about 1.7 ms for the 47-entry table).

Conditions, stated rather than hidden:
1. **Paths more than 64 components below their nearest entry.** The kernel's bound counts from the object to the first
   row, and a `deny_write` target or an `exec.allow` directory is a row that is not an fs entry; Evaluate measures the
   bound on fs entries only, and asks for a deciding entry within it. A path deeper than 64 below its nearest fs entry
   but within 64 of such a row, or of a watch or implicit row whose inherited answer comes from further up, is decided
   by the row in the plane and refused `path-unresolved` (or unmatched) by Evaluate. The generated tables do not reach it.
   Mount crossings are not part of this disagreement: the kernel's walk counts path components as `Find` does (R7).
   Only a climb that crosses more mounts than levels (stacked mounts) differs, refused bound by the kernel alone.
2. **A rename above every write entry** of a directory holding a `deny_write` target is refused by both, for the same
   reason; Evaluate names the target, the plane (no row there) the nearest entry.
3. **Another name of a keyed file** (a hard link made before the run): Landlock's rule is on the inode, so the neutral
   READ_FILE reaches every name of it. The plane's row is on the same inode and already decides every name as the
   canonical one; the neutral right widens Landlock there to at most what the canonical path grants, never a write.
4. **Two exec entries naming one inode under two names** (hard links, both allowed) needed two exec rows under one
   key; T4's fill refused Prepare on the duplicate rather than keep one. *Resolved 2026-09-30 (§6 E15, ADR 0025's
   note of that day):* an exec row is keyed by the link (inode, directory, name), so each listed link has its own row
   under its own entry; the fill refuses only one link twice (`TestPlanPlaneFillRefuses`,
   `TestPlaneFillKeysEachHardLinkOfOneInode`, `TestPlaneFillRefusesOneLinkTwice`).
5. **Neutral rules on sealed deny nodes.** An enforced `deny_read` target keyed by the plane gets READ_DIR, which its
   ancestors' levels already grant; the builder's I11 guard (no union onto a sealed entry) must admit this one union
   (T6), or the target stays unpinned and the identity check refuses a recycled pointer.
6. **Cost at the cap.** *Resolved:* `CompilePlane` indexes the table's entries by path once (`rowindex.go`, ADR 0028
   S1's index), so each row walks only its own ancestors and the compile is near-linear in the table; the search per
   row over the entries it replaced took seconds for 4096 fs entries. The indexed compiler answers every random table
   as that quadratic one does (`TestCompilePlaneMatchesOracle`; `BenchmarkCompilePlaneScale` at the caps, in
   `planerows_scale_test.go`).
7. **The descriptor cap is the real cap.** Every keyed path is held at an O_PATH descriptor for the run, beside the
   Landlock plan's own (a `deny_read` target among many siblings holds every sibling), so the launcher's
   `RLIMIT_NOFILE` binds before 4096 rows: measured as root in the KVM guest (soft = hard = 4096), tables of about
   3,800 to 4,000 keyed paths failed Prepare with `EMFILE`. *Settled 2026-09-30:* the Landlock plan is held to a budget
   read before its first open (`landlock.FDBudget`: the soft limit, raised to one under the hard one where lower, less what the
   process holds and a reserve of a sixteenth of it, 64 to 256), and a plan that needs more is refused naming the cap
   (`FDCapError`, E11), never an `EMFILE`; `PlaneRows.FitFDs` holds the keyed paths to the same budget in compile
   (`PlaneDiagnostic`), in selection and at Prepare (`decide.ErrPlaneCap` with `FDCap`). *Amended 2026-10-05:* a
   budget below its reserve (`ulimit -n 100`) is a cap of 0 (`enforce.PlaneFDCap`), not the negative `Cap` that
   `FitFDs` read as unknown and refused nothing at, so selection gives an auto run tier cgroup where Prepare's
   budget would refuse it; -1 is kept for a budget that cannot be read. An auto run of a table the
   plane cannot hold, over the maps or the descriptors (the mounted-root rows of R12 counted in both) or with two fs
   entries one file under two names (`cgroup.ErrPlaneSharedInode`), is given tier cgroup by `enforce.Select`, which
   asks the one check Prepare makes (`holdablePlaneRows`), with a warning naming why, where the plane runs it if its
   rows fit and the listener otherwise; a run pinned to bpflsm (`--tier bpflsm`, `tier: bpflsm`, the machine config)
   keeps Prepare's refusal (`ErrPlaneCannotHold`, exit 125) (`TestSelectAutoFallsBelowAPlaneThatCannotHoldTheTable`,
   `TestSelectAutoFallsBelowWhatPrepareRefuses`, `TestSelectAutoAsksWhatPrepareAsks`,
   `TestPrepareHoldsThePlanToTheFDBudget`, `TestPlaneDiagnosticCountsTheDescriptorCap`; the boundary as root:
   `TestPlaneCapBoundaryNeverEMFILE`).

### 2.5 Built at T8 (doctor's mode probe, selection and `bpf.plane`)

TIER3-PLAN T8 built doctor's half of R18, R19 and R21 (`internal/doctor` plane.go, planeprobe.go, planepin.go);
the backend that loads a mode for a run (T6, §2.9) reads the answer through the seam below, and so does the one that
constructs tier `bpflsm` (T7, §2.10).

- **Preconditions and the build** (R21). From the kernel's BTF: `bpf_loop` (none: no mode) and `bpf_rdonly_cast`
  (the rd build); lockdown from securityfs (`confidentiality` without `bpf_rdonly_cast`: no build, since the
  probe-read build's reads are refused there); Clang LTO from `/proc/config.gz`, `/boot/config-<release>` or
  `/lib/modules/<release>/config` (a file with no `CONFIG_` line answers nothing), else from `.llvm.` suffixes in
  kallsyms (LTO rules fmod_ret mode out; unknown does not). fmod_ret mode also needs a kernel that does not preempt
  kernel code (ADR 0024 (16), *added 2026-11-02, revised 2026-11-03*): preemption none or voluntary, proven, read by
  `internal/doctor` preempt.go. A build that is not PREEMPT_DYNAMIC needs a readable build config setting
  `CONFIG_PREEMPT_NONE` or `CONFIG_PREEMPT_VOLUNTARY` and none of `CONFIG_PREEMPT`, `_LAZY`, `_RT` and `_DYNAMIC`, with
  `uname -v` carrying no PREEMPT flag; a PREEMPT_DYNAMIC build needs `/sys/kernel/debug/sched/preempt` readable now
  and selecting none or voluntary (no boot line, build default or kernel log is read). Full, lazy, RT, an unreadable
  config and an unreadable or unmounted debugfs rule it out, naming the model or what could not be read, with LSM
  mode, `preempt=voluntary` and mounting debugfs as the fixes (`TestPreemptModel`,
  `TestFmodRetNeedsAKernelThatDoesNotPreempt`, golden `plane-preempt-lazy-boot.*`). A test build's
  `TEGO_TEST_PLANE_PREEMPT=waive` waives it and says so on the mode's line. The reading is never kept: an adopted
  pinned answer (`TestAdoptionRechecksPreemption`), a run-probe cache hit (`TestACachedPlaneAnswerIsHeldToTheKernelsModeNow`)
  and the guard's prepared boundary backend (`TestGuardSelectsAgainWhenFmodRetLapses`) are held to a fresh one. LSM mode needs `bpf` in the active LSM list, with the boot
  line as its fix, the live list plus `bpf` in the tool the distribution uses (`update-grub` on Debian and Ubuntu,
  `grubby` on the RHEL family; `TestGRUBFixPerFamily`) (`TestChoosePlaneBuild`, `TestModePrecondition`,
  `TestParseLockdownAndLTO`).
- **Prototype check** (R21). Each hook's target, `bpf_lsm_<hook>` or `security_<fn>`, is a function in BTF whose
  first parameters point to the structs `decide.bpf.c`'s `TEGO_PLANE_HOOK` declares, in order; the row carries
  the kernel's arity (`TestPlanePrototypesResolveHere`, `TestPlaneParamsMatchTheSource`).
- **The functional probe** (R21). Per mode that passed its preconditions, the chosen build's full hook set is
  loaded unpinned into doctor's fds and attached. A child of doctor's binary (`__doctor-plane-probe`) is cloned
  into a scratch cgroup under the invoking uid's delegated subtree; after it has exec'd, that cgroup is armed in the
  probe's own `tego_run_set` as a run whose slot has **no rows maps** (the probe row). A deciding body must refuse
  there (a run-set hit with no rows map is the walk's fail-closed NOROWS, R7 and §7; T3's bodies must keep that),
  so the child's one syscall per hook, for each hook in `bpf.PlaneHooks` this kernel has, must read EACCES
  (every hook's body decides: `bpf.PlaneHook.Decides` is set on each); the same syscalls from doctor,
  outside the cgroup with the row still armed, must pass; BPF run statistics must show each program ran; and the
  scope evidence must hold: `file_open`'s walk counts the probe row's NOROWS at the row's slot, which only the
  scratch cgroup can reach, so the count must rise across the child's syscalls and not across doctor's (R1; T3's
  walk must keep counting it). Decides
  is held to the C by `bpf/tests` `TestPlaneDecidesMatchesTheBodies` (a body decides when it has `return
  -EACCES`), so the ticket that writes a body turns its refusal check on (`TestPlaneRowOK`,
  `TestIntegrationPlaneProbeOnThisKernel`; guest goldens `plane-guest-lsm.golden`, `plane-guest-default.golden`).
  The control cells' helpers are children of doctor's binary too (`__doctor-plane-probe ptrace-target` and
  `ptrace-traceme`). `PTRACE_TRACEME` traces the calling thread only, so the `ptrace_traceme` helper makes it on its
  thread-group leader (an init locks the main goroutine to the startup thread for that argument and the known answers' child alone) and answers
  failed rather than trace from another thread, whose exit would leave a zombie only a `__WALL` wait by its thread
  id reaps and doctor's wait for the helper unanswered; and it blocks every signal first, since a traced thread stops
  at the delivery of any signal, the Go runtime's `SIGURG` included, for a tracer that never resumes it
  (`TestPtraceTracemeHelperIsAlwaysReaped`; *amended 2026-10-16*).
- **The known answers** (R21; `internal/doctor` planeknown.go). The probe row exercises one answer per hook, NOROWS,
  and a verifier before 6.8 has twice hard-wired a walk branch away with every hook still refusing NOROWS (§2.7's
  BOUND cells, §2.11's unix names). So once a mode's rows and scope pass, the probe fills a scratch slot (1 for
  `lsm`, 2 for `fmod_ret`) of its own unpinned row maps, which both modes' programs are loaded over, through the
  real fill (`enforce/cgroup` `ProbeRows`: `planPlaneFill`, the fill build's pass over doctor's descriptors,
  `checkPlaneFill`, the slot header) from O_PATH descriptors of its own fixtures; arms a second scratch cgroup
  as a run of that slot; and has a child there (`__doctor-plane-probe known`, kept on its thread-group leader as the
  `ptrace_traceme` helper is, since doctor reaches the child's mounts through `/proc/<pid>/root`, the leader's view; a
  child whose main is on another thread refuses to start and the probe fails closed, *amended 2026-11-11*,
  `TestTheKnownAnswersChildRefusesToRunOffItsLeader`, `TestIntegrationKnownAnswerChildIsSeenThroughProcRoot`) make one
  action per cell, each held
  to an exact verdict and to what it adds to the slot's counters: a read two levels below a `deny_read` row across
  a tmpfs mount (refused), a read below a row of the slot's previous gen, written by a first fill (passed), a read
  below a row whose identity doctor flips after the fill (refused, `mismatch` +1: the one cell the fill cannot make,
  so doctor reads the row back from its own map to rewrite it, and prints no key), reads 64 and 65 levels below a
  `deny_read` row (refused; the second `bound` +1), an exec in an exec.allow directory row (passed), of the file an
  exec row names (passed) and of a hard link of it under another name (refused), and an rmdir with no write row
  (refused). In a build that enforces name entries (ADR 0043 C9, *added 2026-10-27*) the slot also holds the built-in
  `.env` pair over a scope `nm/p` beneath a write row on `nm`, compiled by `decide.CompilePlane` as a run's are and
  written by the same fill (the slot's name map, its config row and the header's flag), and seven more cells, every
  file made after the fill: a `.env` and a `.ENV` (refused), `.env.example`, a `.env` outside the scope and one beneath
  `node_modules` (passed), a directory renamed within the scope (passed) and one moved out of it (refused), none
  counting. The child makes its two tmpfs mounts (`dr/m`, and `x` for the exec images, a copy of the binary and
  two links, since the fixture base is often a noexec `/run`) in a mount namespace of its own, private from `/`
  down, so no mount is seen outside it or outlives it; doctor opens the paths under them through
  `/proc/<child>/root`. A cell that differs fails the mode, naming the cell, both verdicts and both counter sets;
  a stage that cannot run is a fault, and so is a cell with no answer or one whose action failed with an errno other
  than EACCES, ENOSYS or EOPNOTSUPP (`planeOutcomeFaulted`, as a hook row's; `Faulted`, not cached;
  `TestPlaneModeVerdictFaultsATransientKnownAnswer`). `PlaneModeResult.Known` carries the cells to `--json` and the run-probe cache
  (whose key holds the binary, so no older answer without them is read). `planeKnownFlip`, a test-only switch,
  flips one cell's expected verdict (`TestPlaneKnownCells`, `TestPlaneModeVerdictNeedsEveryKnownAnswer`,
  `TestPlaneKnownFlipRejectsTheMode`, `TestPlaneKnownFixtures`; in the guest
  `TestIntegrationPlaneProbeOnThisKernel`, which logs every cell and what the known answers add to a warm probe,
  held under 200 ms on 6.17, and `TestIntegrationPlaneProbeRejectsAFlippedKnownAnswer`). A mode whose every cell
  matched is kept in the run-probe cache's directory under the run-probe cache's key (boot, kernel, LSM list,
  lockdown, build hash, binary, process), one file per mode and build (`planeknowncache.go`,
  `TestPlaneKnownCacheKeepsOnlyAFullMatch`), and a later probe of that key by a run (`ForRun`; `tego doctor` never reads or keeps it, R27) reads it instead of filling again: only a
  full match is kept, a differing mode removes what was, and a flipped cell neither reads nor keeps. So a warm probe
  of a boot pays the known answers once. Measured 2026-09-30, both modes together: 6.17 `lsm=` boot 34 ms fresh; on
  AL2023 6.1 every look-up or update of a slot through an outer (map-in-map) map costs about 40 ms, which the slots'
  maps made once and kept open by `ProbeRows` avoid (the fills no longer look their slot up, nor the corruption), and
  what remains of a fresh stage there is the preload of the slots and the fill build beside the first mode's probe
  row and the fixtures; a warm probe reads the kept answers. Every cell matched on 6.17 (both boots), RHEL 9.8 5.14
  and AL2023 6.1. At build time, `bpf/tests`
  `TestBPFLoopCallbackStateIsSeededFromMemory` holds every field a `bpf_loop` callback branches on (in a condition,
  through a local, or read by a function the condition passes the state to) to a seed from map or argument memory
  before the loop, never a constant or the zero-initialised stack (`TestCallbackSeedLintCatchesAPlantedFixture`);
  it found the walk inside a superblock seeding `m` with 0, now read from the caller's zeroed hit as `steps` and
  `crossed` are.
- **Selection** (R18, R19). `bpf.plane` (`auto`, `lsm`, `fmod_ret`; `/etc/tego/config.yaml` only,
  `TestPlaneIsTheAdministrators`) selects tier `cgroup`'s mode from the modes that passed: `auto` takes `lsm`
  before `fmod_ret`, else `fanotify`; a pinned mode that failed is `fanotify`, said so (`TestSelectPlane`). Tier
  `bpflsm` needs LSM mode (`TestBPFLSMNeedsLSMMode`). `Report.PlaneFor(tier)` is the backends' seam: tier `bpflsm`
  gets LSM mode or a `PlaneUnavailableError` carrying doctor's fix (the GRUB line where `bpf` is not active),
  never another mode; tier `cgroup` gets the selected mode or the fallback (`TestPlaneFor`).
- **The exec pin cell** (R21, ADR 0048 (7); `internal/doctor` planeexecpin.go). Once a mode's known answers matched,
  the probe fills their slot again at the next gen as Prepare fills a pinned run's (`ProbeRows.FillPinned`: a key of
  doctor's own, the pin flag and doctor's pid namespace; the preload made the slot's pin map with its row maps, off
  the probe's path, since each map-in-map insert costs about 40 ms on 6.1), attaches the mode's pin
  program in its own collection, and has gates in a scratch cgroup armed as that slot's run exec two static probe
  images under the pins doctor writes (`ProbeRows.PutPin`): ADR 0048 (7)'s answers. A mode that fails the cell still
  decides; its runs claim no pins ("exec pins off" on doctor's line). The result is kept with the known answers and
  carried by the answer pin's flags byte.
- **Where the answer lives** (R21). `tego doctor` always probes. D7 carries one row per hook per mode and the
  plane's clause; `--json` carries `plane` (`TestPlaneDoctorGolden`, goldens `plane-{lsm,default}-boot.*.golden`).
  A root run at reach `cgroup` reads the answer from the run-probe cache (per boot, kernel, LSM list, lockdown,
  build and binary; entry format 7), else adopts it from the build's pin directory when the pinned
  `tego_plane_probe` map there records the mode `bpf.plane` would select (`PinPlaneAnswer`, the backend's call
  at T6), and only else probes (`TestAdoptingRunProbesNoPlane`, `TestAdoptPinnedPlane`,
  `TestIntegrationPlanePinRoundTrip`; as root on a real kernel, `TestIntegrationForRunAsRoot`, which adopts
  where a run left this build lingering, as on CI's root-suites host, and probes in a fresh guest). Every path that returns leaves no pin, descriptor, cgroup or fixture
  (`TestIntegrationPlaneProbeCleansUpWhenTheChildFails`, `TestIntegrationDoctorCancelledDuringThePlaneLeavesNothing`);
  a probe killed before it returns leaves its pid-named fixture directory, which the next probe removes once that pid
  no longer runs and the directory is ten minutes old (`TestProbeFixtureDirsSweepAKilledProbesTree`).

### 2.6 Built at T4 (the fill, `bpf/decide_fill.bpf.c`, `enforce/cgroup` `planefill.go`)

TIER3-PLAN T4 built R16 and the fill's half of R6: the code that writes a slot's rows, called by nothing in a run until
T6 wires it into Prepare. What exists:

- **The object.** `bpf/decide_fill.bpf.c`, built twice like the plane (`decide_fill_rd`, `decide_fill_pr`, the reader
  of `struct mount` differing; `bpf.PlaneFillFor` pairs each with its plane build) and registered apart from the tier-2
  and plane objects (`bpf.PlaneFillObjects`; `bpf.Hash` covers it). It declares `tego_plane_rows` and
  `tego_plane_exec_rows` exactly as the plane does (`TestPlaneFillObjectShape`), and the loader replaces them with the
  plane's instances. Its own maps (`maps.h`'s `TEGO_PLANE_FILL_MAPS` block), pinned per build and mode (§2.9): the
  configs keyed by the filling launcher's tgid (`tgid`, `run_idx`, `gen`, the counts `visited`, `matched`, and the
  exec row under construction), and the wanted rows keyed by `tgid << 32 | what << 30 | fd` (one descriptor may carry
  an fs row and an exec row), each template carrying its fill's `gen`. *Amended 2026-09-30 (P4):* the program looks
  up the config of the task reading the iterator (`bpf_get_current_pid_tgid`), the launcher filling, and applies no
  template of another gen, so launchers of one build fill at once with no lock (a dead launcher's templates, even
  under a tgid reused since, are inert; a fill that finds the maps full removes those of launchers that are gone and
  waits for room, up to 10 s); the one-entry config and the per-CPU exec scratch are gone. Structs:
  `events.h`'s `tego_plane_fill_cfg`, `tego_plane_fill_row`, `tego_plane_clear_ctx`.
- **`tego_plane_fill`** (`iter/task_file`, 566-584 verified instructions): for each descriptor of the launcher's tgid
  that has a wanted row, it keys the row by `f_path.dentry->d_inode` (the pointer the walk looks up) with `i_ino`,
  `i_generation`, `s_dev` and the run's gen, and reports `mnt_id` (`real_mount(f_path.mnt)->mnt_id`, through the
  build's reader) and `i_ino`. An exec row takes `parent` (the dentry's `d_parent->d_inode`) with its identity, and the
  template's name, whose length it checks against `d_name.len`; the bytes come from the compiler (a string read needs a
  probe read, which lockdown=confidentiality refuses), and Prepare checks the parent instead (below). A row of this
  run's gen already at the key is a second entry on one inode and fails (`DUP`, naming the first row's `rule_idx`):
  §2.4's condition 4 for exec rows, and a lost row for fs rows. A row of another gen is replaced. Statuses:
  `bpf.PlaneFillStatus`. *Amended 2026-09-30 (§6 E15):* an exec row is keyed by its link,
  `tego_exec_link_key(inode, d_parent->d_inode, name key)` (`bpf/include/plane_name.h`, shared with `bprm_check`),
  and carries the inode pointer; the fill reads the name through the build's reader (`bpf_rdonly_cast` in the rd
  build, so lockdown=confidentiality is no obstacle) and compares it with the template's byte for byte (`NAME`), so a
  `DUP` on an exec row is one link named twice.
- **`tego_plane_clear`** (`SEC("syscall")`, run by `BPF_PROG_TEST_RUN`): deletes the slot's fs and exec rows of every
  gen but `keep_gen` with `bpf_for_each_map_elem`, so no key reaches userspace. The fill runs it only when a map
  refused a row with E2BIG (a slot full of a previous run's rows), keeping this gen's, and fills what did not fit once
  more; T6 calls it off the run's path (Detach, `purgeSlot`, the reaper).
- **Scope.** The link is task-scoped to the launcher's tgid (`bpf_iter_link_info.task.pid`, made by a raw
  `BPF_LINK_CREATE` since cilium/ebpf passes only a map); a kernel that ignores the scope shows every task's
  descriptors, and the program's tgid filter keeps the answer the same. RHEL 9.8's 5.14.0-687 has the scoped link
  backported (AL2023's 6.1 has it upstream; a scoped fill on either was shown only this process's 135 descriptors).
- **The plan** (`planPlaneFill`): one entry per fs row (`rule_idx` its position, `kind` its kind) and per exec row
  (`rule_idx` its entry, the final name and directory) at the descriptor a `heldFD` lookup gives for its path. It
  refuses a table over the cap (`decide.ErrPlaneCap`), gen 0, a keyed path nothing holds, two rows of one kind on one
  descriptor (the Landlock set's E7 dedupe gives two paths on one inode one number: condition 4 again), a name of 0 or
  256+ bytes, and a descriptor whose statx is not its path's lstat. It records each descriptor's `mnt_id` and `ino`
  then, from the same statx (`AT_EMPTY_PATH`, `STATX_INO|STATX_MNT_ID`, 5.8+; fdinfo below), `st_dev` kept for the
  path comparison (a btrfs subvolume's own), and an exec row's directory inode number.
- **The check** (`checkPlaneFill`, R16): every row `OK`; the kernel's (`mnt_id`, `ino`) equal to the plan's (a number
  reused between the plan and the fill); an exec row's parent inode number the directory's. *Amended 2026-09-30:* the
  second fdinfo pass after the fill is dropped: a number reused after the pass keys nothing, since the row was written
  at the inode the kernel reported, the planned one, and the Landlock set's `owns` holds the descriptor from then on
  (`TestPlaneFillFailsOnAReusedDescriptor` fails closed through the kernel's report). Any difference is `ErrPlaneFill` naming each row, and Prepare
  fails. `st_dev` is never compared with `s_dev` (ADR 0025 (2)).
- **The filler** (`planeFiller`): the two programs and the fill's maps loaded once over one plane's row maps, since
  the load (60-220 ms in the guests) is most of a fill's cost; one process's fills through it are serialized, other
  launchers' run beside them (the config and templates are keyed by tgid), and each removes its templates and config
  after the pass. T6 pins it per build and mode and adopts it (§2.9).
- **Tests.** Unit (`internal/runtime/enforce/cgroup`): `TestPlanPlaneFillTemplates`, `TestPlanPlaneFillRefuses`,
  `TestCheckPlaneFill` (reuse before the fill, duplicates, a moved exec file), `TestParseFDInfo`, `TestHostIdentityIsOneStatx`,
  `TestPurgeStaleWantsRemovesOnlyDeadFillsTemplates`, `TestPutRoomPurgesThenWaits`, `TestPlaneFillKeyKeepsEachLaunchersTemplates`,
  `TestFullRows`, `TestErrPlaneFillNamesTheFirstFive`; `internal/bpf` `TestPlaneFillLayoutParity`,
  `TestPlaneFillObjectShape`, `TestPlaneFillCORERelocationsResolve`. Root, in the guest (`root-must-pass.txt`):
  `TestPlaneFillWritesTheContractsRows` (the rows read back by a test-only dump of the values, count and identity),
  `TestPlaneFillFailsOnAReusedDescriptor`, `TestPlaneFillKeysEachHardLinkOfOneInode`, `TestPlaneFillRefusesOneLinkTwice`,
  `TestPlaneFillSlotReuseLeavesStaleRowsAbsent` (a second run's rows are exactly its table beside the first's stale
  ones, the clear removes only those, and a map full of them is cleared and filled again), `TestPlaneFillTiming`,
  `TestPlaneFillUnscopedOnABusyHost`.

**Measured** (KVM guest, 2 GiB, 4 vCPU; each fill after the filler is loaded; ms, rd build / pr build):

| Kernel | filler load | 100 rows | 1000 rows | 4096 rows | clear of 4096 | 100 rows, 200k foreign descriptors, scoped / unscoped |
|---|---|---|---|---|---|---|
| 6.17.0-41 | 63 / 66 | 5.0 / 5.0 | 25 / 22 | 129 / 118 | 0.8-1.5 | 3.1 / 65-69 |
| RHEL 9.8 5.14.0-687 | 148 / 204 | 15 / 7.3 | 86 / 55 | 216 / 290 | 1.4-1.6 | 8-12 / 121-162 |
| AL2023 6.1 (pr only) | - / 148 | - / 12 | - / 101 | - / 234 | 1.7-3.3 | 6.6-18 / 124-142 |

At 4096 rows most of a fill is Prepare's own fdinfo reads (the check, 90-245 ms); the kernel pass is 11-39 ms. The
unscoped pass costs about 0.3-0.7 µs a foreign descriptor, so a kernel without the scoped link pays tens of ms per
Prepare on a busy host; none of the measured rows is such a kernel.

### 2.7 Built at T3 (Step A's bodies in `bpf/decide.bpf.c`)

TIER3-PLAN T3 wrote `file_open`, `bprm_check`, `path_rename`, `path_link`, `path_unlink` and `path_rmdir` over §2.4's
rows, which the fill (T4, §2.6) writes; tier cgroup's backend loads them for a run (T6, §2.9). Each body answers exactly what
`decide.PlaneRows.Decide` and `ExecMatch` answer:

- **The walk** is T2's, stopping at the first current row (rows are complete), now over the object and 64 levels above
  it (`bpf_loop(130)`, `TEGO_PLANE_WALK_ITERS`: a lookup and a mount crossing per level, a crossing taking no step;
  `PlaneRows.Find`'s steps 0 to 64). No row met: kind 0 (a read allowed, a modification refused);
  the bound exhausted without a row or the root, a disconnected dentry, a mismatched identity or a missing rows map:
  refused `path-unresolved`, each counted (the NOROWS count is what doctor's scope check reads).
- **`file_open`** takes one walk: a read (FMODE_READ, the exec image's and PT_INTERP's opens included) refused by
  `PlaneReadDeny`, a modification (FMODE_WRITE, FMODE_CREATED, O_TRUNC) refused without `PlaneModifyAllow`. It decides
  nothing for an object no path names, as Landlock's walk lets it through: an SB_NOUSER superblock (a pipe reopened
  through `/dev/stdout`, a socket), a private inode, a pseudo file on an internal mount (a memfd, an nsfs file). It
  skips a file on a private clone (`tego_internal_mount`, R8), FMODE_BACKING opens included, by the mount alone: it
  reads no FMODE_BACKING bit. Step C reads it (§2.14). Its position moved with a94204f4d48e: bit 25 from 6.5
  (62d53c4a1dfe) until that commit, bit 24 after it. Mainline took it in 6.14 and the 6.12 stable series in 6.12.105;
  RHEL 9.8 (5.14.0-687) and RHEL 10.0 to 10.2 (6.12.0) have not. No version or BTF field marks the move:
  `file_operations.fop_flags` (6.10, 210a03c9d51a) came earlier. Keyed on fop_flags until 2026-11-10, step C tested
  bit 24 on RHEL 9.8 and 10.2 and recognised no backing file there, so an overlay file under a write entry could be
  mprotected executable (measured in guests by `TestPlaneStepCHooksDecide`'s overlay cell and a `tego run`). Step C
  now takes a file with FMODE_NOACCOUNT, which every backing file carries, and bit 24 or 25; the other FMODE_NOACCOUNT
  files are the kernel's own; that no mapping of the agent's holds one is read from mainline code, not measured, and
  not checked in RHEL's sources. No backing file exists where BTF has no `struct backing_file`. The check fails open:
  on a kernel that moves FMODE_BACKING to a third bit, step C would not recognise a backing file and would allow
  such a mapping, and the root suites' overlay cell is the test that shows it.
- **`bprm_check`** decides only when the slot header's `TEGO_SLOT_EXEC_DECIDES` is set (R6): the contract has an
  `exec:` section; `TEGO_SLOT_EXEC_ANON` carries `exec.anonymous`, which decides an anonymous image (an image whose
  dentry is its own parent or unhashed: a memfd, a file unlinked since it was opened) with no rule. A `#!` stage passes.
  Otherwise three arms, any match allowing (every exec entry allows, `ErrPlaneExecVerdict`): the row keyed by the
  file's inode, only under its directory's inode and its name; a name row keyed by `internal/bpf.PlaneNameKey` (FNV-1a
  over the name's words, top bit clear, never 0; `PlaneRows.Names`); and the nearest fs row's `PlaneExecDir`. The
  recorded rule is the lowest exec entry of the first two arms, else the fs row's position with bit 16 set
  (`TEGO_PLANE_RULE_FS_ROW`), which the ledger resolves through `PlaneRow.Exec` (T9). A hard link under another name,
  an unlisted file and a directly invoked loader match no arm.
- **The name compare** reads the dentry's name as at most 32 eight-byte words through the build's reader
  (`bpf_rdonly_cast` of the address as a `struct qstr`, whose first member is a u64, or `bpf_probe_read_kernel`), the
  bytes past `d_name.len` zeroed, and compares length and every word with the row's zero-padded name, each pass a
  `bpf_loop` callback. `d_name.hash` is not used: the kernel salts it with the parent dentry's address, which the
  domain does not pin, so a reclaimed and re-looked-up directory would hash every name anew and refuse allowed execs.
- **`path_rename`**: each end a rename of itself (`PlaneRenameRefused` at depth 0, reason `deny-write-ancestor`, else
  the modification), then REFER by `Strictness`; for a positive destination the reverse too, since `RENAME_EXCHANGE`
  moves it the other way and the 5.14 hook carries no flag. **`path_link`**: the new name a modification, then REFER.
  **`path_unlink`, `path_rmdir`**: a modification at the object. The fmod_ret programs return 0 for an IS_PRIVATE
  directory, the parent `security_path_unlink` and `security_path_rmdir` test, not the object (R4).
- **Recorded**: each decision's `{rule_idx, hook, verdict, reason}` in the task's `tego_plane_scratch` value. Kernel
  reason codes 10 (`refer`) and 11 (`deny-write-ancestor`) are added; the ledger maps them at T9 (`Evaluate` names a
  REFER refusal `rename-outside-contract`).
- **Verified instructions** (6.17 guest; probe-read build / rdonly build, LSM and fmod_ret within 50 of each other):
  `file_open` 936 / 3,096, `bprm_check` 1,904 / 4,012, `path_rename` 954 / 3,114, `path_link` 852 / 3,012,
  `path_unlink` and `path_rmdir` 774 / 2,934, all under the 20,000 budget. A first form whose walk answered several
  questions at once, carrying partial answers from step to step, took 21.5k (44k for `bprm_check`); the complete rows
  let one walk answer every question, in T2's form. The guest has no overlayfs module, so the overlay cell logs and
  does not run there.
- **Tests**: `bpf/tests` `TestPlaneHooksLookTheRunUpFirst`, `TestPlaneEveryHookRecordsItsDecision`,
  `TestPlaneFileOpenNeverAppliesExecRows`, `TestPlaneExecComparesTheWholeName`,
  `TestPlaneRenamesAndLinksKeepTheirRows`; `internal/bpf` `TestPlaneNameKey`, `TestPlaneCapsMatchRowCompiler` (the
  kind bits); and the root `TestPlaneStepAHooksDecide`, which loads both builds in each mode the kernel offers, fills a
  scratch slot through a test-only `iter/task_file` program (`bpf/testonly/plane_fill.bpf.c`, built only with `-tags
  integration,tegobpf`, never embedded in tego) and runs each hook's cells in a child cgroup armed after its exec and
  outside it: reads and writes under each kind, REFER both ways, `mv .git .git.old`, a hard link, an unlisted file, a
  direct loader, PT_INTERP, `#!` stages, name and directory rows, memfd with and without `exec.anonymous`, a stale row
  absent, a corrupted identity refused and counted, a next run's gen, a write through `/dev/stdout`, an overlay write.

Found here, stated as conditions:
1. **Overlay copy-up.** Writing a lower-layer file makes overlayfs open the new upper file with a plain `dentry_open`,
   not a backing open, in the agent's task, so `file_open` decides it on the upper path, where no row lies: an unmatched
   modification, refused. The user's own open was decided on the merged file. Step B's overlay cell must settle it (a
   row on the upper directory from the fill, or a skip keyed on something the agent cannot forge;
   `current->cred != real_cred` is not one, since io_uring personalities override credentials too). *Settled at T13
   (§2.12):* the skip, keyed on the open's mount being a private clone (`mnt_ns` is `MNT_NS_INTERNAL`), which no name
   the agent opens resolves through.
2. **An exec by an `exec.allow` directory names a row, not an entry**, in the kernel's record (bit 16). *Resolved at T9
   (§2.8):* the ledger reads the bit and names the row's `exec.allow` entry (`decide.PlaneRows.ExecRuleAt`,
   `PlaneRow.Exec`); the u16 `rule_idx` of an exec record cannot carry bit 16, so `sched_process_exec` carries it in
   `tego_ev_exec.plane` and the plane's own sample carries the whole u32.

With the bodies deciding, `bpf.PlaneHook.Decides` is set for all six hooks, so doctor's probe (§2.5) requires each to
refuse in its probe row. Its exec now runs a memfd copy of the binary, made once per probe (both modes share it)
before the first row is armed, inherited by each mode's child and reused by doctor's own exec
(`TestPlaneChildExecsTheInheritedImage`, `TestIntegrationPlaneProbeCopiesTheBinaryOnce`): an exec of a
named file is refused by `file_open` (no rows map) before `bprm_check` is reached, while a memfd is no path to
`file_open` and reaches `bprm_check`'s own NOROWS refusal.

### 2.8 Built at T9 (the record: `trace_proc.bpf.c`, `decide.bpf.c`, `internal/runtime/observe`)

TIER3-PLAN T9 puts the plane's decisions on the ledger, one line per action (ADR 0017 (a)), in both modes. The backend
that loads the plane for a run is T6's; the root cell loads it beside the recorder as T6 will.

- **The decision, per call.** `tego_plane_decision` gains `obj`, the object the decision was on (`file_open`'s
  `struct file *`, `bprm_check`'s `bprm->file`, `path_rename`'s old dentry, `path_link`'s new dentry, `path_unlink`'s
  and `path_rmdir`'s dentry), and a second slot for `bprm_check`'s last decision (`exec_obj`, `exec_rule`,
  `exec_verdict`), since the ELF loader's open of `PT_INTERP` comes between `bprm_check` and `sched_process_exec` and
  replaces the first. `tego_plane_scratch` is declared by the recorder's object too and pinned by name beside the
  shared maps, so both objects hold one map (`bpf.TraceMaps`).
- **The recorder's fexit reads it (R23).** On `file_open`, `path_unlink`, `path_rmdir`, `path_rename` and `path_link`
  the fexit takes the task's decision right after its run lookup, only when its hook and object are this call's (an
  earlier call's value, left where the plane returned before deciding or an earlier LSM refused first, is told apart
  by the object) and consumes it. A plane refusal, with the chain's `-EACCES`, is stamped on the record's header
  (verdict, reason, `rule_idx`), so the action's one fs line is the plane's refusal; the chain's return stays the
  verdict. `sched_process_exec` takes `bprm_check`'s kept decision on `bprm->file` and, for an exec the plane
  allowed, names its rule on the record (`tego_ev_exec.plane`: an entry, or an `exec.allow` directory's fs row).
- **The plane's own sample on `bprm_check` (R23).** The one step A hook no recorder fexit wraps writes
  `struct tego_ev_plane` (kind 19) to the run's ring at each refusal, under `record: off` too: the refused exec's
  one line, through the plane's one sample writer (`tego_plane_own_sample`, which sets every field of the record,
  0 for those an exec does not carry: reserved ring memory is not zeroed). Its name is `bprm->filename`, read as at
  most 32 words through the build's reader into the task's own
  buffer (`tego_plane_path_buf`, task storage created for the sample and deleted after it, pinned by name since
  §2.18 so later runs adopt the plane; not per CPU,
  which a preempted sample shares with the next refused exec on its CPU), up to the word holding its NUL with the bytes past it cleared, so the rdonly
  build reads it under lockdown=confidentiality and fmod_ret mode needs no `bpf_d_path`. `bprm_check` verifies 3,208
  instructions (probe-read build) and 5,294 (rdonly) on 6.17, from 1,904 and 4,012.
- **Reasons.** A walk refused for a row whose inode no longer carries its identity is reason code 12
  (`identity-mismatch`), no longer `path-unresolved`, and so is `bprm_check`'s file arm. The ledger keeps `reason`
  in the closed set (REASON-CHANNEL: a v1 reader validates it, so a new code would not be additive) and names the
  plane's own cause in the additive `plane_reason`: `refer` (reason `rename-outside-contract`, or
  `write-outside-contract` for a link), `deny-write-ancestor` (`rename-outside-contract`), `identity-mismatch`
  (`path-unresolved`). A read refused is `read-denied` (§4's "denied-read").
- **Rules (R24).** The recorder compiles the run's plane rows (`decide.CompilePlane`, what the backend fills from)
  on its first plane line and names `rule_idx` by the hook's question: `PlaneRows.RowName` (the deciding entry, else
  the row's nearest entry, else `unmatched`: `PlaneRefusal`'s naming, so the ledger names what `compile --test`'s
  bpflsm column names), `NamedAt` for REFER, the deny_write target for `deny-write-ancestor`, an exec entry's
  position, and `ExecRuleAt` for bit 16. Every such line carries `mechanism: plane` and `decision_plane` from the mode
  the runtime reports (`enforce.DecisionPlaneReporter`, which T6/T7's handle implements; `observe.SetDecisionPlane`).
- **Exec lines at tier 3 (supervisor R7a, amended).** With the plane deciding the run's execs, the supervisor writes
  no line for an exec it continues (`supervisor.Options.KernelExecs`) and the recorder writes exec lines
  (`SupervisorExecs` false): the plane's refusal sample, or `sched_process_exec` named by the plane's rule. The
  supervisor's allow was a prediction the plane may overturn on the image the kernel actually loads; ADR 0016 (4)'s
  departure ("the supervisor for every exec, until an exec record carries the grant it ran under") ends where the
  plane's `rule_idx` is that grant. The supervisor keeps the execs it refuses or answers itself.
- **The counters (built 2026-09-30).** Nothing read `tego_plane_counters` but Prepare's zeroing and doctor's probe.
  The runtime now asks the handle for the run's slot's counters once at run end (`enforce.PlaneCounterReporter`,
  `Handle.PlaneCounters`), after the cgroup has emptied and the queue drained and before `run_end`, so the counts are
  final and nothing has cleared them (Detach clears the slot's rows, never its counters; the slot's next
  `prepareSlot` zeroes them). Each non-zero counter is one `gap what=enforce` line, `why` `plane-identity-mismatch`,
  `plane-path-unresolved`, `plane-walk-bound` or `plane-no-rows`, `count` its value and `decision_plane` the mode; a
  slot that cannot be read is one `plane-counters-unread` line with no count, never silence. An orphaned run's reaper
  does the same before its `run_end orphaned`, from the pinned map of the mode and slot its argv names
  (`cgroupenforce.ReadPlaneCounters`), and only while the run's scope still exists, since the slot is then still
  carried. A counter a later ticket adds to the struct is one more entry in `planeCounts`.
- **Tests.** `bpf/tests` `TestPlaneExecRefusalsWriteTheirSample`, `TestRecorderTakesThePlaneDecision`,
  `TestPlaneEveryHookRecordsItsDecision` (`obj`); `internal/bpf` layout parity of `PlaneDecision` and `PlaneEvent`,
  `TestPlaneCapsMatchRowCompiler` (the bit); `decide` `TestPlaneRuleIndexNames` (the bit-16 case); observe
  `TestRecorderNamesPlaneRefusals`, `TestRecorderKeepsPlaneRefusalsUnderRecordOff`, `TestDecodePlaneExec`;
  supervisor `TestExecContinuedIsTheKernelsLineUnderThePlane`; runtime `TestKernelRecorderOwnsExecsUnderThePlane`;
  and the root `TestIntegrationPlaneRefusalIsOneLine` in the 6.17 guest, both modes: with the plane loaded beside the
  recorder, pinned into one directory, and a slot filled through T4's fill, a read under `deny_read`, a rename out of
  it, `mv .git .git.old`, an unlink under it and a write-open outside every entry are each one fs line and an
  unlisted exec one exec line, refused with `mechanism: plane`, the mode, and the rule and reason
  `decide.PlaneEvaluator` gives; an exec by an `exec.allow` directory and one by a file entry are one allow line each,
  named `exec[./tools]` (bit 16) and `exec[./bin/t]`.

Found here, stated as conditions:
1. **REFER is not reachable from a compiled table** (both ends must allow the modification first, §2.4), so its
   ledger naming is held by the unit cells only; the kernel cell covers it with T3's hand-made row.
2. **An exec the supervisor continued that fails in the kernel outside the plane** (`ENOEXEC`, `ETXTBSY`) had no exec
   line at tier 3. *Closed 2026-10-04 (§2.19):* negative syscall results supply one observed terminal line; image-open and bprm refusals supply that exec's kernel evidence.
3. **Attribution when two exec arms match.** `bprm_check` prefers an entry of the file or name arm to the directory
   arm's row, where `ExecMatch` takes the lowest entry of all three; the line then names another allowing entry
   than `compile --test` does (the verdict is the same). *Closed 2026-10-04:* filesystem rows carry the actual lowest exec entry index separately from their encoded ledger row index; all three arms compare the real declaration order (`TestPlaneRunExecEntryPrecedence`).
4. **observe's reason index table** (`reasonByIndex`) numbered codes 8 and up differently from `enum
   tego_reason_code`; nothing sent them to it on a kernel-refused record, and the plane's codes go through
   `bpf.ReasonCode` instead. *Fixed 2026-09-29* (enforce-cgroup-observe R9's Changes): the table is the kernel's
   numbering, read from events.h by its test; no ledger line was mislabelled.

### 2.9 Built at T6 (the plane in tier cgroup's backend, `enforce/cgroup` plane.go, planerun.go)

TIER3-PLAN T6 is the join: when doctor selects a plane mode for tier cgroup (`Report.PlaneFor`), `Report.Select`
hands it to the backend (`enforce.Plane`, `cgroup.Options.Plane`, with doctor's `PinPlaneAnswer` bound to the
choice), and a run's opens, execs, renames, links, unlinks and rmdirs are decided by `decide.bpf.c` in that mode.

- **Load and adopt (R18, R20).** With the build's tier-2 objects loaded or adopted, `newBPFPlane` loads the mode's six
  programs of the chosen build, or adopts them, pinned under `/sys/fs/bpf/tego/<hash>-<mode>/{maps,progs,links}`. The
  maps the plane shares with tier 2 (the run set, the rings, and `tego_plane_scratch`, now declared by `trace_proc`
  too) are the build's own, handed to the loader (`adoptObjectIn` checks a pinned program reads exactly those); the
  plane's own (`tego_plane_rows`, `tego_plane_exec_rows`, `tego_plane_counters`) are pinned in the mode's
  directory. The links are pinned like the build's tracing links, so linger keeps them; the build's removal
  (`pinLayout.remove`, the last launcher out, `SweepBuilds`, `tego gc`) takes its plane directories first, a sweep
  removes a plane directory whose build is gone, and `tego doctor`'s build list names a build's planes.
  (`TestSweepTakesABuildsPlanesWithIt`, `TestPlaneDirOf`.)
- **The answer pin (R21).** Once loaded, the plane pins doctor's answer as `<hash>-<mode>/tego_plane_probe`, so a
  run adopting the build probes nothing (`TestPlaneRunEndToEnd` checks the pin).
- **Row maps once per slot (R6).** `prepareSlot` creates a slot's two inner maps the first time the slot is used and
  keeps them; a run writes its rows with its gen (the slot's epoch, R6), zeroes the slot's counters, and never creates or drops
  an inner map on its path. The fill's programs and maps are pinned once under `<hash>-<mode>/fill` and adopted (the
  load is most of a fill's cost); pinning it takes the build's fill lock (`/run/tego/bpf-<hash>-plane-<mode>.lock`),
  and, since 2026-09-30 (§2.6), fills and clears take none. bpffs refuses a name with a dot, so the fill is pinned
  under the lock rather than renamed into place.
- **The fill (R16, R17).** The run's rows are compiled once (`decide.CompilePlane`, in `enforce`'s adapter) and ride on
  the run to both halves: the Landlock plan holds every keyed path and adds its neutral rule (`landlock.Run.Plane`,
  the `kindPlaneKey` stage; the one union a sealed deny node takes, §2.4's condition 5), and exposes its descriptors
  (`Handle.PlaneHeld`); `fillPlane`, Prepare's last step, fills the slot through T4's fill from them. A keyed path
  that does not exist keys no row (`planeFillPlan.Absent`), as the plan skips it. The bare-name rows (T3's open condition,
  `bpf.PlaneNameKey`, only with an `exec:` section) and, last, the slot header (R6) are written from userspace, since their keys are no inode (`TestExecKeyRows`,
  `TestPlanPlaneFillSkipsAKeyedPathThatDoesNotExist`, `TestPlaneKeysAreHeldWithTheirNeutralRules`). *Amended 2026-09-30
  (§6 E15):* an exec row whose held descriptor was opened at another name of its inode (the E7 dedupe) gets one of its
  own at its link, identity only (`planeExecLinks`, `TestPlaneExecLinksHoldEachLinkItsEntryNames`).
- **Arming (R15).** Arm's run-set row, after the stage's exec, now carries the run's mode (`tego_run.plane`, the
  byte that was padding): each plane program decides only runs prepared in its own mode. One build's run set holds
  runs of every mode, and both modes can be attached at once (`bpf.plane` changed while a build lingers); without it a
  plane would decide a fanotify run, or the other mode's, with rows it does not hold and refuse its every open
  (NOROWS). doctor's probe row and T3's cells name their mode too (`TestPlaneHooksDecideOnlyTheirModesRuns`).
- **No listener (R22).** A plane-mode run makes no fanotify group and places no mark; the capability line keeps read
  and exec denial (`TestPlaneRunPrepareArmDetach`, and the end-to-end run's check that the launcher holds no
  fanotify group). A table the plane cannot express (over the cap, E13; an exec entry that does not allow) runs on the
  listener instead, whole, with the reason in the run's log (`Handle.DecisionPlane`,
  `TestPlaneFallsBackToTheListenerForATableItCannotHold`): at tier cgroup the listener enforces it all, which is no
  quieter run; tier `bpflsm` refuses such a table at Prepare instead (T7, §2.10).
- **The clear (R6).** A run's Prepare clears its slot beside the slot's purge, Detach clears it once the run-set row
  is gone, and a reaper's `PurgeRun` clears every dead launcher's slot through each mode's pinned fill
  (`openPinnedPlanes`), all T4's in-kernel clear (`TestPlaneLauncherKillLeavesTheRunDecidedAndTheReaperPurges`,
  `TestPlaneStaleRowsOfTheSlotsLastRunAreAbsent`).
- **The record.** It is T9's (§2.8): the fexit programs take the plane's decision by hook and object, and the
  plane's refusal lines carry its reason and `plane_reason`; T6 loads the plane over the recorder's
  `tego_plane_scratch`, so the two objects share it in every run.
- **Tests, root in the guest, both boots.** `TestPlaneRunEndToEnd` (a real `tego run --tier cgroup` per mode the
  machine passes, pinned with the test build's `TEGO_TEST_PLANE`, and on the listener for contrast): a deny_read
  under a write entry refused with EACCES, a write outside every entry, an unlisted exec and an allowed binary's hard
  link under another name refused, a rename and a hard link carrying a deny_read file out of its tree refused, `mv .git
  .git.old` refused while a write in the repository goes ahead, the launcher holding no fanotify group, the slot's rows
  present while the run lives and gone after it, and source=kernel refusal lines with the plane's reasons.
  `TestPlaneConcurrentRunsOfOneBuildAreIsolated` (§6 case 1), `TestPlaneLauncherKillLeavesTheRunDecidedAndTheReaperPurges`
  (§6 case 11, with `drop_caches`), `TestPlaneStaleRowsOfTheSlotsLastRunAreAbsent` (§6 case 2 through the backend),
  and the package's existing tier-2 suites, which now run in the plane mode the guest selects
  (`TestTier2ConcurrentRunsOfOneBuild`'s 2, 8 and 32 runs among them). ADR 0017's kernel runner runs tier cgroup on the
  listener and once per plane mode available, the plane modes against the plane column (`test/conformance`); two
  cells differed there and were baselined: a mkdir under a deny_read nested in a write entry (`path_mkdir`, step B,
  T13) and an unlisted script, which the plane passes at its `#!` stage while the Landlock floor refuses it. The
  second was the column's error, not the kernel's: since 2026-09-30 the column is the plane intersected with the
  floor (`decide.ScriptFloor`, R9) and the cell expects refused at every tier, with no baseline entry. Both guest
  boots (lsm=...,bpf and without bpf) pass every suite.
- **doctor.** A run-probe cache entry adopted from a pinned build holds that build's one mode; a pin of the other
  mode is no longer answered by it (`PlaneState.answers`), where it ran every later run on the listener until the
  boot's cache ended (`TestACachedAnswerOfOneModeDoesNotAnswerAPinOfTheOther`).
- **The keyed files, reported (2026-10-17, ADR 0055).** After a fill the handle reports the files its fs rows were
  written at (`enforce.PlaneKeyedReporter`, `Handle.PlaneKeyed`): each row's path with the device and inode its
  descriptor had when the plan was made, the identity the fill's check holds the written row to; mount-only rows
  (R12) and exec rows are left out. Nothing a row decides changes. An adoption reads it: a boundary fails before the
  attach when the agent owner's `~/.tego` is not keyed at the directory its table was compiled against, and the
  held-file count asks the rows by the path of the row keyed at a held file's inode (a hard link). Shown on the
  kernel by `TestPlaneRunKeyedFilesAreTheInodesItDecides` (the identities are a stat's; a hard link of a deny_read
  file and a deny_read directory renamed after the fill are refused) and in units by
  `TestPlaneKeyedIsWhereTheFsRowsAreWritten`.

Found here, stated as conditions:
1. **The supervisor's half of R22.** The supervisor still refuses, best effort, what the plane now decides race-free
   (C30 a and b, C31, R15c): a rename out of a deny_read tree or `mv .git` is refused by it before the kernel's hook
   runs, with its own line. Handing those to the kernel is a later change of the supervisor. *T16 (§2.13) built the
   fs half as a narrowed filter, enabled at §2.15; the exec half is built at §2.19.*
2. **Stale rows are cleared, not only absent.** Every Prepare clears its slot (T4's clear, milliseconds at most), so
   a stale row reaches a run only when a clear failed; the walk's gen check is what keeps that exact.

### 2.10 Built at T7 (tier `bpflsm`: `enforce/bpflsm`, `enforce` buildable.go and select.go, doctor's run scope)

TIER3-PLAN T7 wires tier `bpflsm` as ADR 0024 (4) has it: the plane in LSM mode over tier cgroup's backend, not a
backend of its own.

- **The constructor (R19).** `bpflsm.New` is the tier-2 backend (`enforce/cgroup`) with `Options.Tier` set to
  `bpflsm` and the plane required in LSM mode; any other mode, the fanotify fallback included, is refused
  (`cgroup.ErrNeedsLSMMode`, `TestNewNeedsLSMMode`). The backend then answers `Tier()` as `bpflsm`, takes only a
  table compiled for `bpflsm` (and tier cgroup's only one compiled for `cgroup`), writes tier 3 in the run-set row,
  and keeps its run's capability set within tier 3's column: the run's set is the one a tier-2 plane run has, so
  `fs.deny_chmod`, which step B's `path_chmod` decides, is not claimed (`TestTierBPFLSMIsThePlaneInLSMMode`). *As
  built at T13 (§2.12):* `path_chmod` protects `deny_write` targets only, so the static column's `deny chmod` cell
  says no, naming that (`TestChmodDeniedOnlyAtTier3`).
- **No fallback (I7, §6 case 13).** Where tier cgroup runs a table the plane cannot hold on the fanotify listener
  (§2.9), tier `bpflsm` refuses it at the top of Prepare, before any kernel state or slot: `ErrPlaneCannotHold`,
  naming the cause (over the cap, `decide.ErrPlaneCap`; an exec entry that does not allow) and the way out
  (narrow the entries, or `--tier cgroup` / `tier: cgroup`). A plane in another mode handed to it is refused there
  too (`TestTierBPFLSMRefusesATableThePlaneCannotHold`, `TestTierBPFLSMNeedsLSMMode`).
- **Build and selection (R19).** `enforce.Buildable(bpflsm)` is tier cgroup's answer: the plane's objects are embedded
  with tier 2's, so a build with them builds tier 3 (`TestBuildable`). `enforce.LSMPlane` hands `Select` doctor's
  `Report.PlaneFor(bpflsm)`, the LSM-mode choice with its answer pin, or doctor's refusal; `Report.Select` always
  passes it. Without a plane in LSM mode, a probe offering tier `bpflsm` does not make it selectable: an auto run is
  warned and runs at tier cgroup, and `--tier bpflsm` is refused with doctor's reason as the fix
  (`TestLSMPlaneReachesTheTierThreeBackend`, `TestSelectFromDoctorProbe`). In doctor's derivation that never
  happens, since LSM mode passing is one of tier `bpflsm`'s checks. A tier-3 run's Prepare compiles the plane rows
  once and composes tier 1 with them, as a tier-2 plane run does.
- **The refusal of case 12.** `--tier bpflsm` where LSM mode does not pass is refused at selection, before Prepare
  and before run_start, exit 125 `[tier-unavailable]`: "tier bpflsm pinned but not available" with doctor's line for
  the tier, which where `bpf` is not an active LSM names that and the GRUB line (`TestReportSelectsTierBPFLSM`,
  `-tags tegobpf`). An auto run there runs at tier cgroup.
- **The run's probe scope (limits-check-doctor-cli R27).** An auto run as root in a build with the objects now reaches
  tier `bpflsm`, so reach `bpflsm` is scoped as reach `cgroup` is rather than taking doctor's full probe on every
  run: tier cgroup's checks with the run-probe cache and the pinned build's answer, and D6's LSM list without its
  counting program. LSM mode's probe counts the plane's own LSM programs running, which is the proof D6's program
  gives, and a cached or pinned answer is one this boot's probe gave. D7's own tier-3 and capture rows are not
  loaded; tier `bpflsm`'s fix line reads tier cgroup's rows, which are the ones it needs
  (`TestRunAtReachBPFLSMProbesAsReachCgroupAndTheLSMList`, `TestRunReportIsDoctorsAtAndBelowItsReach`, `TestReach`).
- **The supervisor's chmod line.** A mode change read `refused` at tier `bpflsm` while no loaded hook refuses one
  (`path_chmod` is step B); it reads `allow` at every tier until step B lands (supervisor R17,
  `TestTruncateAndChmodLeaveOneLine`). *Reconciled at T13 (§2.12):* with `path_chmod` loaded, the supervisor refuses
  a notified chmod beneath a `deny_write` target wherever a plane mode decides the run, tier `bpflsm` included, and
  reads every other mode change `allow`, as the plane decides it (`TestChmodUnderThePlaneRefusesADenyWriteTarget`).
- **Tests, root in the guest.** `TestTierBPFLSMRunEndToEnd`: on the lsm=...,bpf boot `tego run --tier bpflsm` and an
  auto run each run the §2.9 contract with the plane's cells (EACCES, REFER, `mv .git`, no fanotify group, the rows
  present and cleared) and a run_start naming tier `bpflsm`; on a boot without `bpf`, `--tier bpflsm` exits 125
  with the GRUB line and no run_start, and an auto run gets tier cgroup.

Found here, stated as conditions:
1. **Step B's chmod.** The supervisor's tier-3 chmod refusal is withdrawn until `path_chmod` is loaded (T13), which
   restores it; the capability line already says so. *Settled at T13 (§2.12):* the refusal is restored for a
   `deny_write` target, the one a plane refuses; `fs.deny_chmod` (a contract's chmod refusal outside write entries)
   stays unclaimed, since the plane does not decide it.
2. **An oversized auto table.** An auto contract whose rows exceed the cap reached tier `bpflsm` as root and was
   refused at Prepare (compile warns for it, §2.4); `tier: cgroup` ran it on the listener. *Settled 2026-09-30 (§2.4
   condition 7):* selection gives such an auto run tier cgroup, with a warning naming the cap, and only a run pinned
   to bpflsm is refused. Widening the rows (a row per directory) is the later change §2.4 names.

### 2.11 Built at T15 (step D: unix names below 6.7, `decide.bpf.c`, `enforce/cgroup` plane.go, planerun.go)

Below 6.7 there is no `cgroup/connect_unix` or `sendmsg_unix`, so tier 2 decided no unix name in the kernel
(enforce-cgroup-observe §6 E1). Where a plane mode runs, step D decides them in its place, by the rule and from the
rows those programs use on 6.7+, so one contract gets one unix verdict on every kernel with a plane.

- **The hooks.** `socket_connect` and `socket_sendmsg`, not ADR 0024's `unix_stream_connect` and `unix_may_send`
  (ADR 0024's 2026-09-29 T15 note): those run after the path lookup and see the peer socket, not the name the
  contract's rows and the relay's `/proc/self/fd/<n>` are keyed by, and `unix_may_send` runs for every datagram of a
  connected socket as well. `security_socket_connect` runs before the protocol's connect and
  `security_socket_sendmsg` before `unix_dgram_sendmsg`, each on the kernel's own copy of the caller's `sockaddr_un`
  (`move_addr_to_kernel`, `____sys_sendmsg`'s copy of `msg_name`), which no thread of the caller can rewrite after the
  hook reads it. `socket_connect` decides an `AF_UNIX` address on an `AF_UNIX` socket (a datagram socket's
  `AF_UNSPEC` disconnect is no name); `socket_sendmsg` decides a `SOCK_DGRAM` send with a `msg_namelen`, which is
  exactly when `unix_dgram_sendmsg` runs `sendmsg_unix`. Io_uring's `IORING_OP_CONNECT` and `IORING_OP_SENDMSG` reach
  both hooks too.
- **The run is the socket's.** The supervisor relays every unix connect of the agent from the launcher's cgroup on a
  `pidfd_getfd` duplicate of the agent's socket (supervisor R11), so a lookup keyed by the caller would miss every
  relayed connect, as it did for tier 2 (enforce-cgroup-observe §5 R1). The body looks up the socket's cgroup
  (`sk_cgrp_data.cgroup->kn->id`, fixed when the socket was made) in the run set (`tego_unix_sock_run`); R1's
  single lookup and miss-returns-0 hold with that key (`TestPlaneHooksLookTheRunUpFirst`). `sock_cgroup_data` carries
  the `struct cgroup *` from 5.15 upstream, and in RHEL 9.8's 5.14 and AL2023's 6.1 (their BTF, read in the guest).
- **The decision.** `tego_plane_unix_reason` is `cgroup_net.bpf.c`'s `tego_unix_decide`: an abstract name admitted
  when a `unix:` entry names its bytes exactly; a relative connect refused and a relative datagram left to tier 1;
  `/proc/self/fd/<digits>` admitted on a connect from the policy's relay cgroup only; any other absolute name
  admitted when spelled canonically and a `unix:` or write entry admits it in `tego_unix_names`, which Prepare
  fills on every kernel and the loader hands the plane by name. A write entry's row admits any name under it: the
  hooks see a name, not the socket it reaches, so they do not hold supervisor R11a's rule that the implicit admit is
  for a socket the run bound (2026-10-16). The supervisor decides every unix connect and addressed datagram first and
  holds it; what this row alone decides — a datagram whose name, or the file it leads to, changed after that
  decision (a sibling rewriting the name, a rename or symlink swap by a process of the run), an `io_uring` connect or
  unix-addressed send under `io_uring: true` — is supervisor R11a's disclosed residual, which a peer check in `unix_stream_connect` and
  `unix_may_send` by the peer socket's run (`tego_unix_sock_run`) would close. The canonical-spelling rule
  (`tego_unix_canon_byte`) and `tego_unix_relay_name` moved to `include/common.h`, one copy for both tiers
  (`TestPlaneUnixHooksDecideAsConnectUnixDoes`); the plane runs the rule through `bpf_loop`
  (`tego_plane_unix_canonical`), since the loop the verifier walks, as `cgroup_net` has it, took each socket hook
  past 34,000 verified instructions on 5.14, over the plane's budget of 20,000. Its callback reads each byte of the
  kernel's copy through the build's reader, and its state starts from the slot policy's `zero` byte rather than a
  constant: AL2023's 6.1 verifies a `bpf_loop` callback once, from the state of its first call (6.8's "verify callbacks
  as if they are called unknown number of times" fixed that; RHEL 9.8 carries it), took the state for a known 0,
  hard-wired the branches that need another, and refused every absolute name at its second `/`
  (`TestPlaneUnixHooksDecide` found it there; `TestPlaneUnixHooksDecideAsConnectUnixDoes` holds the map-byte start).
  The key's name is read through the build's reader too: `bpf_rdonly_cast` byte by byte, or one
  `bpf_probe_read_kernel` of `sun_path`.
- **The slot's policy.** The fill writes `tego_plane_unix_policy[slot]` with the run's gen on every plane run:
  `decides` where the plane's unix hooks are loaded and the contract has a `net:` section (none decides nothing,
  SEMANTICS §1), and the launcher's cgroup as the relay's (`Handle.relayCgroup`, which fails Prepare for a launcher
  inside the run's cgroup as it fails Attach). A hook that finds no policy of the run's gen refuses and counts
  `norows`, so doctor's probe row, which has none, is refused by both hooks (`TestPlaneFillCarriesTheUnixPolicy`).
- **Loaded only below 6.7.** `bpf.PlaneHook.Unix` marks the two hooks; `newBPFPlane` leaves them out where the build
  loaded `connect_unix` (6.7+), so no name is decided twice and a host of 6.7+ pays nothing for them. doctor's
  probe exercises all eight hooks on every kernel: a connect to a listening socket and a datagram to a bound one, from
  sockets the probe child makes before the row is armed.
- **Discipline.** 0 or -EACCES (`TestPlaneReturnsOnlyZeroOrEACCES`); a refusal is `EACCES` where 6.7+'s cgroup
  programs answer `EPERM`. Each decision is recorded in the task's scratch value under
  `TEGO_HOOK_SOCKET_CONNECT`/`SOCKET_SENDMSG`, reason `net-not-allowed` (or `path-unresolved` with no policy), rule
  the name row's `rule_idx`.
- **Tests, root in the guest.** `TestPlaneUnixHooksDecide` (internal/bpf: both builds, each mode the boot offers, the
  helper's connects and datagrams, the relay from this cgroup and without a relay cgroup, a socket of no run, a
  policy of another gen refused and counted, a policy that decides nothing) and `TestPlaneUnixVerdictOnRealKernel`
  (enforce/cgroup: a plane-mode run through Prepare, Attach and Arm, held to `TestUnixVerdictOnRealKernel`'s cells
  with EACCES; on 6.7+ it loads the build as below 6.7). Run on RHEL 9 5.14 and AL2023 6.1 (lsm), and 6.17 in its
  lsm and default (fmod_ret) boots.

Stated as conditions:
1. **No ledger line of the plane's own.** ADR 0024 (11) lists the unix hooks among those whose refusals the plane
   samples. As built they write none, as `connect_unix` and `sendmsg_unix` write none on 6.7+: a unix connect's or
   datagram's one line is the supervisor's (enforce-cgroup-observe §5 R7, supervisor R13b), with the same two
   disagreements R7 states for 6.7+ (a datagram the kernel refused recorded `best_effort`; a non-canonical name the
   supervisor cleans and admits recorded `allow`). The per-run record of which path decided is R7's, built as
   `run_start.net_guarantees.unix` (true where `connect_unix` and `sendmsg_unix`, or these two hooks, are attached).
   *Amended 2026-10-05:* the condition stands for the plane's own line, and the two disagreements are
   closed on the supervisor's: told that the plane decides unix names with `EACCES` (`Handle.KernelDatagrams`), the
   supervisor refuses, with `EACCES`, a datagram these hooks would refuse, and that refusal is its one line, without
   `best_effort` (supervisor R13b; `TestTier2DatagramLineIsTheKernels` on RHEL 9's 5.14).
2. **Tier cgroup without a plane keeps §6 E1.** Below 6.7 a run on the fanotify fallback still has no kernel unix
   decision; `TestUnixVerdictOnRealKernel` asserts that and skips there.

### 2.12 Built at T13 (Step B: `bpf/decide_stepb.h`, the plane rows, the socket policy and `io_uring`)

TIER3-PLAN T13 wrote Step B's bodies in `bpf/decide_stepb.h`, which `decide.bpf.c` includes after Step A's, over the
same macro, walk, readers and records; tier cgroup's backend loads them with Step A's (§2.9).

- **Creates and truncates (R13).** `path_mknod` (called from `may_o_create`, before an `O_CREAT` open makes its
  inode), `path_mkdir`, `path_symlink`, `path_truncate` and `file_truncate` decide a modification at their object with
  the walk that crosses mounts, as `path_unlink` does (reason `mkdir-outside-contract` for mkdir, else
  `write-outside-contract`); a negative dentry's walk starts at its directory. `file_truncate` skips what `file_open`
  skips. The fmod_ret programs reproduce each `security_path_*` wrapper's IS_PRIVATE exit (R4). The recorder's fexit
  programs on the five take the decision by hook and object as Step A's do (§2.8), the mknod one on the create it
  holds for the open that follows too, and `tego_truncate` on the `O_TRUNC` open it ends.
- **Attribute changes (R12).** `path_chmod`, `path_chown`, `inode_setxattr`, `inode_removexattr`, `inode_set_acl` and
  `inode_remove_acl` walk inside the object's superblock (`tego_plane_walk` with no vfsmount: `d_parent` to the
  superblock's root, which ends it as ROOT) and refuse only where the nearest row carries `TEGO_ROW_PROTECTED`
  (`decide.PlaneProtected`: a `deny_write` target at or above the row; the row's `Modify` names the target), or where
  the walk failed closed (R7). Any other row, and no row, passes: Landlock governs none of these calls. Timestamps
  and inode flags (`inode_setattr`, `file_ioctl`) have no hook and are a residual (§9). The inode
  hooks' first argument, a `struct user_namespace *` below 6.3 and a `struct mnt_idmap *` from 6.3, is declared
  `void *` and never read; doctor's prototype check asks only that it exists (`planeParams`). An object no path names
  (SB_NOUSER, a private inode, a kernel mount's pseudo file such as a memfd) is no decision. In LSM mode a program's 0
  lets the `bpf_lsm_` stub's own default stand, so `security_inode_setxattr`'s capability check below 6.11 still runs.
- **Mounted-root rows (R12).** `decide.PlaneRows.WithMounts` adds, for each mountpoint of the launcher's mountinfo
  (`cgroup.MountPoints`) strictly below a `deny_write` target and not a row's path, a mount row at the mounted root
  carrying the nearest row above's kind with `TEGO_ROW_MOUNT_ONLY` and that row's position as `rule_idx`; the path
  joins `Keyed` with its neutral rule, so the domain pins it. `CompilePlane`'s rows and positions are unchanged, so the
  recorder, which compiles without mounts, names every decision alike. The walk that crosses mounts passes a mount-only
  row (it meets the target's own row above the mountpoint); the walk inside a superblock stops at it. A mounted root
  that is a keyed row's inode already keeps that row; mount rows count against the slot's cap (a table over it runs
  on the listener, `cgroup.Run.PlaneErr`; at tier bpflsm Prepare refuses it with that error as `ErrPlaneCannotHold`,
  never compiling the rows again without the mounted roots, `TestTier3PlaneTakesTheCallersError`).
- **socket_create (R14; ADR 0018 (5)).** Under a `net:` section, which the slot header says (`TEGO_SLOT_NET_DECIDES`,
  with `TEGO_SLOT_NET_ICMP` for a port-0 entry; written by `bpfPlane.fill` from `netPolicyOf`, the filter's
  `SocketArmFor` answer; R6), the filter's
  allowlist: AF_UNIX, NETLINK_ROUTE (ADR 0128), and AF_INET or AF_INET6 as TCP or UDP streams and datagrams (ICMP datagrams with an ICMP entry). A kernel socket
  (`kern != 0`) passes before anything else; with the header's net flag clear, nothing is refused; a slot with no
  header of the run's gen fails closed (NOROWS). Every path to `__sock_create` reaches it, `socketpair(2)`'s and io_uring's
  `IORING_OP_SOCKET` included, which the seccomp filter cannot see.
- **The plane's own samples (R23).** No recorder fexit wraps the attribute hooks or `socket_create`, so their refusals
  write `struct tego_ev_plane` (now with `dev`, `dir_ino`, `family`, `type`, `protocol`) as `TEGO_EV_PLANE_ATTR`
  (20) and `TEGO_EV_PLANE_SOCKET` (21), under `record: off` too. The recorder names an attribute change as a file
  operation is named (the directory index over `dev`, `dir_ino` and the final component, read through the build's
  reader) with op `chmod` (chmod and the ACL hooks), `chown` or `xattr` (additive within v1), rule the `deny_write`
  target (`PlaneRows.RowName` for `PlaneProtect`), mechanism plane; a socket as a `refused` line naming the triple,
  reason `net-not-allowed`, rule unmatched, mechanism plane (`RefusedPayload.Mechanism`, additive within v1), as the
  supervisor's own socket refusal is.
- **Optional hooks (R3, §6 E14).** `bpf.PlaneHook.Optional` marks `file_truncate` (below 6.2 `ftruncate(2)` and an
  `O_TRUNC` open reach `path_truncate`) and the ACL hooks (below 6.2 an ACL is an xattr write, `inode_setxattr`'s).
  `bpf.PlaneHooksFor` leaves one out where the kernel's BTF lacks its target: the backend's load and links
  (`kernelHasFunc`), doctor's probe (an `Absent` row naming the hook that decides its rule there, which fails
  nothing) and the root tests alike. doctor's probe exercises every Step B hook in the scratch cgroup: a mknod, a
  mkdir, a symlink, a truncate, an ftruncate of a descriptor the child opened before the row was armed, a chmod, a
  chown to the same owner, a trusted xattr set and removed, an ACL set and removed (the filesystem's `ENOTSUP` or
  `ENODATA` after the hook passed is a pass) and a TCP socket.
- **Overlay copy-up (§2.7's condition 1, settled).** `file_open` and `file_truncate` return 0 for a file on a mount
  whose `mnt_ns` is `MNT_NS_INTERNAL` (`ERR_PTR(-EINVAL)`, what `clone_private_mount` gives overlayfs' private clones
  of its layers): copy-up's plain `dentry_open` of the new upper file and of the lower one, in the agent's task, after
  the agent's open of the merged file was decided. No name the agent opens resolves through a private clone; a
  detached mount (`mnt_ns` NULL) is not skipped. `TestPlaneStepAHooksDecide`'s overlay cells write a lower file under a
  write row (copied up, allowed) and under a row refusing modifications (refused on the merged file); the guest loads
  overlayfs with `VM_MODULES=overlay` (test/vm/root-suites.sh).
- **`io_uring: true` (ADR 0018 (5)).** The inherited filter drops its `io_uring_*` ENOSYS arm (enforce-landlock R10)
  for a contract that declares `io_uring: true` when `landlock.Run.IOUring` says the tier decides every submission in
  the kernel: tier cgroup or bpflsm with a plane mode (`Run.PlaneRows` set), whose unix names `cgroup/connect_unix`
  decides on 6.7+ and step D's hooks below (§2.11; `cgroup.IOUringDecided`). Elsewhere `io_uring` stays ENOSYS and `enforce.Select` warns
  (`CodeIOUring`), judging by the tier it chose: tier cgroup with a plane mode admits it only where the plane holds
  the table's rows (a table it cannot hold, `ErrPlaneCap` or `ErrPlaneExecVerdict`, runs on the fanotify listener,
  and the warning names why); tier bpflsm with its LSM plane admits it without a warning.
- **The record's plane naming, wired.** `enforce.DecisionPlaneReporter`, which T9 defined for the runtime to name the
  mode on the plane's lines and hand a continued exec's line to the kernel, had no implementation: tier cgroup's
  handle now implements it (`Handle.DecisionPlane`; the former `(string, error)` form is `Handle.PlaneChoice`). With a
  plane mode, the supervisor also refuses a chmod it is notified of (`record: full`) beneath a `deny_write` target by
  supervisor.md R15c's predicate (`supervisor.Options.PlaneAttrs`), so the action's one line is that refusal rather
  than an allow the kernel then overturns (I8).
- **Verified instructions** (6.17 guest; probe-read build / rdonly build, LSM mode; fmod_ret within 35):
  `path_mknod`, `path_mkdir` and `path_symlink` 902 / 3,786, `path_truncate` 939 / 3,823, `file_truncate` 988 / 3,847,
  `path_chmod` and `path_chown` 2,357 / 5,232, the xattr and ACL hooks 2,352 / 5,227, `socket_create` 337 / 337. The
  walk's mount-only and superblock branches moved Step A's: `file_open` 1,048 / 3,924, `bprm_check` 3,507 / 6,330. All
  18 programs of a build load in 150-360 ms (fmod_ret faster than LSM mode).
- **Kernels** (root suites in the KVM guest): 6.17 with `bpf` in `lsm=` (both modes) and on its default boot
  (fmod_ret), all 18 hooks; RHEL 9.8's 5.14, all 18 (its BTF carries `file_truncate` and the ACL hooks; its
  `kernel.io_uring_disabled` leaves the io_uring cells unrun); AL2023's 6.1, 15 hooks with `file_truncate` and the ACL
  hooks absent. With step D merged (§2.11), doctor's probe runs 20 of 20 hooks per mode on 6.17 and 5.14 and 17 of 17
  on 6.1, step B's and step D's coexisting in one object. On 6.1, the probe-read build, the truncate and setfacl cells
  are refused by `path_truncate` and `inode_setxattr` and doctor's rows name the absent hooks.
- **Tests.** `bpf/tests` `TestPlaneStepBCreatesAreModifications`, `TestPlaneAttributeHooksProtectOnly`,
  `TestPlaneStepBRefusalsWriteTheirSample`, `TestPlaneSocketCreateIsTheAllowlist`, `TestPlaneFileOpenSkipsPrivateClones`
  and Step A's extended to the new hooks; `decide` `TestPlaneRowsProtectDenyWriteTargets`, `TestPlaneRowsWithMounts`;
  `cgroup` `TestMountPointsReadsMountinfo`, `TestPlanPlaneFillMountRows`, `TestNetPolicyRow`, `TestChoosePlaneTakesTheCallersError`;
  `landlock` `TestFilterIOUringArm`, `TestPrepareAdmitsIOUringOnlyWithThePlane`; `enforce`
  `TestSelectWarnsWhenIOUringHasNoEffect`; supervisor `TestChmodUnderThePlaneRefusesADenyWriteTarget`; observe
  `TestRecorderNamesPlaneAttrAndSocketRefusals`, `TestDecodePlaneAttrAndSocket`; doctor `TestPlaneModeVerdict`,
  `TestPlaneRowOK`, `TestPlaneParamsMatchTheSource`. Root, in the guest (`root-must-pass.txt`):
  `TestPlaneStepBHooksDecide` (both builds, both modes), `TestPlaneRunEndToEnd`'s step B cells (a mkdir and a create
  under the nested `deny_read` refused with nothing left, a chmod and a setfacl of `.git/config` refused, each one
  line), `TestPlaneRunRefusesIOUring` (C40 now checks startup refusal), and the conformance cell `fs/mkdir-in-deny-read-nested-in-write`, which passes in
  both plane modes and left `baseline.json`.

Found here, stated as conditions:
1. **io_uring below 6.7.** Without `cgroup/connect_unix` an io_uring connect to a unix socket would pass the
   supervisor's relay, which decides `unix:` entries there. Step D's hooks (T15, §2.11) decide those names in the
   kernel wherever a plane mode runs below 6.7, so `io_uring: true` is admitted with a plane mode on every kernel
   (`cgroup.IOUringDecided`).
2. **A mounted root reachable elsewhere.** A mount row keys the mounted root's inode: a bind mount below a
   `deny_write` target of a directory from elsewhere protects that directory's attribute changes wherever it is
   reached (an over-refusal of chmod, chown, xattr and ACL only; the walk that crosses mounts passes the row). A mount
   made below a target after Prepare has no row; neither the agent nor its launcher can mount.
3. **A disconnected dentry.** The attribute walk refuses one that is not a kernel mount's pseudo file
   (`path-unresolved`); the agent reaches none, since `open_by_handle_at` is ENOSYS.
4. **`MNT_NS_INTERNAL` is a kernel-internal value** (`fs/mount.h`); the overlay cells ran on the 6.17 guest only,
   since the matrix rows load no module. A kernel that changed it would refuse copy-up again (fail closed), which the
   overlay cell names.
5. **An attribute refusal's path.** The recorder resolves the sample's directory through the rule table's directory
   index, which holds the fs entries' directories; a file directly in a `deny_write` target that no entry names (a
   repository's `.git/config`) is named by the raw `dev:ino` identifier and its final component, with the target as
   the rule (`TestPlaneRunEndToEnd`'s setfacl cell).
6. **Exec lines in plane runs.** With `DecisionPlaneReporter` wired, a tier cgroup run a plane mode decides writes an
   allowed exec's one line from the kernel (supervisor R7a as T9 amended it); `TestTier2ConcurrentRunsOfOneBuild` now
   counts either source and refuses a kernel exec line no plane named.

### 2.13 Built at T16 (step E: `enforce/landlock` filter.go, `enforce/cgroup` planerun.go, `internal/runtime` run.go)

TIER3-PLAN T16 builds R27's notification drop per loaded hook, the fs half of R22's supervisor half with it (the
supervisor refuses nothing it is not notified of), and gates it on the record.

- **The hook set.** The plane records the hooks it loaded and attached for the run's mode (`bpfPlane.hooks`, by
  `bpf.PlaneHook.Name`). Step D's hooks are absent on 6.7+ and the optional ones (`file_truncate` below 6.2, the ACL
  hooks below 6.2) where BTF lacks them (`bpf.PlaneHook.Optional`); a missing hook keeps every notification it
  would replace.
- **The narrowed filter.** Prepare, once the plane is filled, asks the inherited Landlock handle for its filter less
  what those hooks decide (`landlock.Handle.PlaneFilter`, `planeSkips`): `unlink`, `rmdir`, `rename*` and `link*`
  with step A's hooks (`unlinkat` needs `path_rmdir` too, for `AT_REMOVEDIR`); `mkdir*`, `mknod*`, `symlink*` and
  truncate(2) with step B's `path_mkdir`, `path_mknod`, `path_symlink` and `path_truncate`; the open family's write
  arm and `creat` only with `file_open` and `path_mknod` both, since a create refused at `file_open` alone leaves its
  file behind. Nothing is left out with an `fs.ask` entry. *Amended at §2.15:* under `record: full` the open family
  (the write arm and `creat`) stays notified and the rest is left out; T16 left nothing out there. The errno arms are unchanged;
  execs, connects, the mount family, the keyring, System V IPC and chmod stay notified.
- **The gate.** `SeccompFilter` hands the narrowed filter out only after the runtime calls `UsePlaneFilter`
  (`enforce.PlaneFilterer`), and the runtime calls it only when the run's kernel recorder names path-hook records
  by path on its own (`runtime.PathHookNamer`). With mutations left out the supervisor keeps no walk cache
  (`supervisor.Options.PlaneFS`, `TestWalkCacheIsOffWhenThePlaneTakesMutations`).
- **Tests.** Unit: the filter per hook set on both architectures, the errno arms kept, `PlaneFilter`, the tier's
  hook set and its use only once asked, the runtime's gate. Root, in the 6.17 guest (lsm=...,bpf), both modes:
  `TestPlaneRunEndToEnd` holds the refused `mv .git`, unlisted exec and hard-linked exec to
  one line each; `TestConformanceKernel` at tier cgroup in both plane modes has no disagreement beyond its baseline.

Stated as conditions:
1. **Not enabled: the recorder cannot name a path hook's record on its own.** *Lifted at §2.15: the recorder names
   each such record by the parent directory's path the kernel walks, and the gate is open.* Measured with the gate forced open in
   the guest: the refused `mv out/repo/.git` became one kernel line named `26:17/.git` under rule `unmatched`, since
   the recorder names a path hook's record by its directory index (`observe` `matchDir`) and names anything in a
   directory no entry is (every subdirectory of a write entry) as `dev:ino/name` with no rule; the supervisor's
   naming (`ContinuedFS`) came from the notification now gone. Allowed mutations in a worktree's subdirectories
   would read `unmatched`, which `drift` counts. `observe.Recorder` implements `PathHookNamer` once it names such
   records by path (bpf_d_path on the path hooks from 6.8, or a walk to the nearest indexed directory).
2. **The exec hand-over was not built at this checkpoint.** Continuing an exec the supervisor would refuse, for bprm_check to refuse,
   left no ledger line in ADR 0017's kernel runner (`exec-unlisted-binary`, `exec-unlisted-copy-in-write-entry`,
   `exec-hard-link-to-granted` at both plane modes): an unlisted binary is refused first by the Landlock floor's
   EXECUTE at the exec open, which no fexit line records as an exec, and the plane's own `bprm_check` sample names
   the spelling passed (`bprm->filename`), not the path the cell names. The supervisor keeps its exec, deny_write and
   loader refusals and their lines until an exec's kernel refusal is one named line. *Closed 2026-10-04 at §2.19.*
3. **Kill test 4 at the plane tiers fails Prepare on a multi-call coreutils.** On Ubuntu 25.10's uutils `dirname`
   and `mkdir` are hard links of one inode in one directory, and the fill keys one exec row per inode, so kill test
   4's pip contract fails Prepare at tier cgroup (plane) and `bpflsm` on the test machine and in its guests. The timing
   below replaced the two names with their directory (`/usr/lib/cargo/bin/coreutils/`). *Fixed 2026-09-30* (§6 E15):
   exec rows are keyed per link, and kill test 4 runs its own contract: at tier `bpflsm` on `debian-13` (6.12,
   `VM_KT4_TIERS=bpflsm`) pip passed 19/20 (3116 / 3793 / 6232 ms), npm 19/20 (742 / 1199 / 1484 ms), and go 0/20 on
   time alone (206 / 716 / 412 ms), the go condition this section already states.

Kill test 4 pip, `debian-13` guest (6.12, bpf in the default LSM list, so tier cgroup runs in lsm mode), 20 runs,
baseline / under tego medians / budget in ms, on a shared host:
- before T16: cgroup 19/20, 5083 / 5604 / 10166; bpflsm 19/20, 7516 / 11905 / 15032; load average 9.3 at the
  start, 38.0 at the end.
- T16 with the gate forced open (the narrowed filter in use): cgroup 19/20, 7102 / 7253 / 14204; bpflsm 20/20,
  6463 / 7270 / 12926; load average 17.7 at the start, 17.3 at the end. Over baseline: cgroup 1.10x to 1.02x,
  bpflsm 1.58x to 1.12x, on a load too uneven to call more than a direction.

### 2.14 Built at T14 (step C: PROT_EXEC mappings, `bpf/decide_stepc.h`; the memfd arm, `enforce/landlock`)

ADR 0027's two hooks, in their own file, included last by `decide.bpf.c`; and R27's memfd half.

- **The hooks.** `mmap_file` and `file_mprotect`, each one body emitting both SEC forms (R4). Both return 0 before
  the run-set lookup when there is no file or no PROT_EXEC, so a host process pays a branch on an anonymous or
  non-executable map, and a run whose slot header says no `exec:` section is decided nothing.
  `mmap_file`'s LSM hook and its `security_` function take different arguments,
  `bpf_lsm_mmap_file(file, reqprot, prot, flags)` against `security_mmap_file(file, prot, flags)`: the body reads four
  `u64` parameters by mode, and in fmod_ret mode its fourth is the function's return slot, never read (doctor's
  prototype check asks each target for its own, `planeParamsFmodRet`). Both decide on the effective prot: the LSM
  hook is handed `mmap_prot(file, reqprot)`, which the fmod_ret program, running ahead of that computation,
  reproduces (`tego_mmap_prot`: READ_IMPLIES_EXEC adds PROT_EXEC to a PROT_READ map on a mount that is not noexec);
  `file_mprotect` is handed the effective prot in both modes and never reads reqprot (ADR 0027's amendment).
- **The decision** (`tego_map_decide`, reason `exec-not-allowed`, rule `exec-map` in R26's words). In order: a
  slot with no header of the run's gen refuses (the probe row's answer); a header without `TEGO_SLOT_EXEC_DECIDES`
  (no `exec:` section) passes; an S_PRIVATE inode (the shmem file behind `MAP_SHARED|MAP_ANONYMOUS`, a SysV segment)
  is anonymous memory, not a file, and passes (GAPS A2); only then is the task's scratch value taken (as `bprm_check`
  orders it: a refused task-storage allocation refuses, counting `unresolved`, only a run the contract restricts);
  no exec-rows map refuses and counts `norows`; (c) execmem (a writable and executable private file map, and an mprotect to that) and execmod
  (an mprotect making a private file map with copy-on-write pages executable, `anon_vma` set) refuse whatever the
  file; (a) an anonymous file (unhashed or its own parent, as `bprm_check` reads one, or an SB_NOUSER superblock)
  follows `exec.anonymous`; (b) otherwise the nearest fs row decides: anything but a write row, or a write row with
  `PlaneExecDir`, allows; under a write row the file needs `bprm_check`'s file arm (its exec row under its
  directory's inode and its name) or name arm, so whatever the plane lets run the ELF loader may map, and a hard link
  under another name may not. A mismatched exec row refuses `identity-mismatch` and counts; a failed walk refuses
  `path-unresolved`. `file_mprotect` decides only a mapping that becomes executable (no VM_EXEC yet), and execmem on
  one that is.
- **Overlay mappings.** From 6.8 a vma of an overlayfs file carries the backing file, whose `f_path` is the real
  layer's; `file_mprotect` then walks from `backing_file_user_path()` (`struct backing_file.user_path`, read by the
  build's reader and taken only where BTF has the field) and decides by the fs rows alone: no exec row names the
  real layer's inode, so an exec file entry does not cover an overlay mapping mprotected executable (condition 3).
  `mmap_file` sees the user's own file on every kernel; before 6.8 the backing file's `f_path` is the user's path.
- **The memfd arm (R27, TIER3-PLAN §10's "gated on the probe").** `bpf.PlaneDecidesMappings` reports that the plane's
  hooks include step C's deciding bodies; a run carries plane rows only in a mode doctor's probe selected, which
  requires each hook, these two included, to refuse its probe syscall in the probe row (R21; the probe maps a
  one-page memfd `PROT_READ|PROT_EXEC`, and maps it `PROT_READ` and mprotects it executable). Tier 1's composition
  for such a run (`enforce.inheritedRun`, `landlock.Run.PlaneMaps`) drops the arm refusing every `memfd_create` on a
  kernel without MFD_NOEXEC_SEAL (AL2023's 6.1): `bprm_check` refuses an anonymous image's exec and `mmap_file` its
  PROT_EXEC map race-free, so a data memfd need not be refused with them. The sealing arm stays where the kernel has
  the flag, as defense in depth; tier 1 and the fanotify fallback keep both arms as they were.
- **Recorded**, in the task's scratch value under `TEGO_HOOK_MMAP_FILE` (21) and `TEGO_HOOK_FILE_MPROTECT` (22), the
  object `mmap_file`'s `struct file *` and `file_mprotect`'s `vm_area_struct *`. No recorder fexit wraps either hook,
  so every refusal writes the plane's own sample (R23; `tego_map_refuse` over step B's `tego_plane_own_sample`),
  `TEGO_EV_PLANE_MAP` (22), naming the file as an attribute change's sample does (its directory's dev and ino and its
  final component), or with no name for an anonymous file or an overlay's backing file (`path_ok` 1 with an empty
  name: nameless on purpose; a name asked for and not read, a refused task-storage allocation, is `path_ok` 0 and reads
  as the truncated path with a `path-truncated` gap, never `anonymous`). The recorder writes it as one
  `refused` line (a mapping is no action kind of the record): `op` `mmap` or `mprotect`, `target` the file resolved
  through the directory index, the truncated path (and a path-truncated gap) for a named file whose name the plane could
  not read, or `anonymous`, `reason: exec-not-allowed`, `rule: exec-map` (`path-unresolved` and the
  unmatched rule where the plane failed closed), `mechanism: plane` (`TestRecorderNamesPlaneMapRefusals`).
- **Verified instructions** (6.17 guest; probe-read build / rdonly build, the modes within 60 of each other):
  `mmap_file` 4,119 / 5,723, `file_mprotect` 4,108 / 5,878, under the 20,000 budget. A first rdonly build passed the
  backing file's user path to the global walk as the pointer `bpf_rdonly_cast` returns, which the verifier refuses
  for a scalar argument; it is laundered through the scratch value as every other walk's is.
- **Tests.** `bpf/tests` `TestPlaneMapHooksReturnBeforeTheRunLookup`, `TestPlaneMapDecidesOnTheEffectiveProt`,
  `TestPlaneMapPolicy`, and the step files read with `decide.bpf.c` by every plane source test; observe
  `TestRecorderNamesPlaneMapRefusals`; doctor
  `TestPlaneParamsMatchTheSource`, `TestPlanePrototypesResolveHere`, `TestPlaneDoctorGolden`; landlock
  `TestMemfdArmDroppedWhereThePlaneMaps`; enforce `TestInheritedRunDropsTheMemfdArmOnlyWithAPlane`; root in the guest,
  `TestPlaneStepCHooksDecide` (internal/bpf: both builds, each mode the boot offers, a dropped file mapped and
  mprotected executable refused and readable allowed, an exec.allow directory, an exec file entry and its hard link
  under another name, a name row, a mismatched exec row counted, a file under no write row, execmem and execmod,
  READ_IMPLIES_EXEC by mmap and by PROT_NONE mprotected to PROT_READ, a memfd with and without `exec.anonymous`,
  shared anonymous memory, the ELF loader mapping an allowed binary under a write row and its libraries, no `exec:`
  section, the same maps outside the run, an overlay mapping where the module exists) and
  `TestPlaneExecMapRunEndToEnd` (enforce/cgroup: `tego run` of a python3 agent in each plane mode and on the
  fanotify listener: its interpreter and libraries load, a dropped copy of a system library fails `dlopen` and one
  under an exec.allow directory loads, mmap, mprotect, execmod and READ_IMPLIES_EXEC spellings, and `memfd_create`
  admitted where the kernel lacks MFD_NOEXEC_SEAL and the plane maps, while its memfd never maps executable).

Stated as conditions:
1. **A refused map is a `refused` line, not an action.** The record has no mapping kind, so the line names the
   operation and the file but no process lineage of an exec; `drift` sees it among refusals only. The agent sees
   EACCES (a native module's import fails, `dlopen` reports "failed to map segment").
2. **The compile warning and the model are built (2026-09-30, the T14 follow-up).** `tego compile` warns
   `exec-map` for each native-module tree under a write entry that no `exec.allow` entry covers, at a tier a plane
   may decide, naming the entry to add (agent-contract E39, `TestNativeCodeUnderWriteEntryWarns`); the scan is
   bounded (20,000 entries, 10 levels), so a tree beyond it is not named. `compile --test` answers `exec.map` rows:
   allowed at tiers landlock and cgroup, where no mmap hook decides, and at bpflsm the plane's answer,
   `decide.PlaneEvaluator` equal to the root model (`TestEvaluateExecMapSplitsByTier`,
   `TestPlaneEvaluatorMapMatchesEvaluate`, `TestCompileTestBPFLSMColumnGolden`); ADR 0017's `exec` fixture carries two
   `map-exec` cells (a file dropped under the write entry, refused `exec-map` at bpflsm and in each plane mode; a
   readable binary outside it, allowed everywhere), with an invariant for the plane tiers. Kill test 4's pip kind
   names its install directory in `exec.allow` and its workload asserts markupsafe's `_speedups` extension loads.
   Kill test 4 on the `debian-13` guest (6.12, lsm mode), this change and the tree before T14 back to back with the
   same harness, 20 runs each, medians baseline / under tego in ms: pip at bpflsm 20/20 (5882 / 8541) here against
   10/20 (5976 / 9506) before, `_speedups` loading in every run; pip at cgroup 2/20 (7243 / 15104) against 19/20
   (6990 / 7419); npm and go fail the 2x bound at the plane tiers on both sides (go 0/20 at cgroup and bpflsm on
   both). The host's load average rose from 6 to 25 during the first run and stayed at 21 to 26 through the second,
   too uneven to attribute a timing to step C; every failure at the plane tiers was a wall over budget, none a
   refusal. Kill test 4's pip kind needed its multi-call coreutils (uutils) named by directory to fill (§2.13's
   condition 3).
3. **An overlay mapping made executable by `mprotect` is decided by fs rows alone on 6.8+**, and a build without
   `bpf_rdonly_cast` reads the user path through probe reads, which only a kernel below 6.2 (no backing files) needs.
4. **Anonymous memory stays GAPS A2**: MAP_ANONYMOUS, shared anonymous memory and SysV segments (S_PRIVATE inodes)
   are not files, so a JIT (Node, Java, V8) is unaffected and a JIT's W^X dance on them is not decided.

### 2.15 Built at T16's naming (the recorder names path hooks by path: `trace_proc.bpf.c` `tego_dir_walk`, `internal/runtime/observe`)

§2.13's condition 1 kept the drop off: with a mutation no longer notified, the fsop record is its one line, and it
named a file in a directory the recorder's index does not hold (every subdirectory of a write entry) as
`dev:ino/name` under rule `unmatched`. Three ways to name such a record by its full path were weighed; the decision is
(c), recorded in ADR 0016's 2026-09-30 note.

- **(a) `bpf_d_path`.** Checked in `kernel/trace/bpf_trace.c` and `kernel/bpf/bpf_lsm.c` at v5.14, v6.1 and v6.17
  (`bpf_d_path_allowed`): a tracing program (the recorder's fexit, the plane's fmod_ret) may call it only at
  `btf_allowlist_d_path`'s functions, the same set on all three (`security_file_permission`,
  `security_inode_getattr`, `security_file_open`, `security_path_truncate`, `vfs_truncate`, `vfs_fallocate`,
  `dentry_open`, `vfs_getattr`, `filp_close`), so `security_path_truncate` is the one path hook; an LSM program only
  at a hook of `sleepable_lsm_hooks`, which holds no `path_*` hook at v5.14 or v6.1 (`path_notify` only) and
  `path_unlink`, `path_mkdir`, `path_rmdir`, `path_truncate`, `path_symlink`, `path_link`, `path_rename`,
  `path_chmod` and `path_chown` at v6.17 (from 6.8). It would name records only in lsm mode on 6.8+, and only from
  the plane, which stays string-free (`TestPlaneWalkHasNoStringOps`). Rejected.
- **(b) Userspace, from `(dev, ino)` through the plane's held descriptors.** The launcher holds an `O_PATH`
  descriptor per entry (ADR 0023), not per subdirectory: naming a subdirectory's inode means searching the entry's
  subtree after the fact, when a rename may already have moved it (a wrong path) and at a cost that grows with the
  tree. It is exact only for the directories the index already holds. Rejected.
- **(c) A dentry walk in the recorder's fexit, into the record (chosen).** For a run whose run-set row names a plane
  mode (`tego_run.plane`), each fsop program walks the parent directory of each side (a rename's and a link's two;
  a link's source by its `d_parent` on the new name's mount, which `vfs_link` requires; a truncate's file by its
  `d_parent`) as `d_path` walks: `d_parent` to the mount's root, `mnt_mountpoint` and `mnt_parent` across a mount,
  until `current->fs->root`, prepending each name right to left into `dir` (`dir2`), 256 bytes each in the record,
  with `dir_off` where the path starts (`struct tego_ev_fsop` is 1128 bytes, was 608). The buffer is the record's
  own: no map, and no per-CPU buffer another task's program could overwrite on the same CPU (ADR 0024's T9 lesson).
  **Never a wrong path:** each level's `d_seq` (which `__d_move` writes around every change of a dentry's parent and
  name) is read before its parent and name and kept, and a second pass walks the chain again and compares: equal and
  even sequences all the way up mean the same chain (the first level is the same dentry, and a dentry whose
  sequence did not move kept its parent), anything else is `TEGO_DIR_RACED`. **Mounts:** `d_path` also reads
  `mount_lock`, no BTF symbol either; each crossing's parent mount and mountpoint are kept on the first pass and read
  again at the same crossing on the second, so a mount moved between the passes, or read torn mid-move, is `RACED`
  too (a move done before the first read and not undone before the second leaves a path true in between, as
  `d_path`'s would be). **Ordering:** a seqcount reader needs `smp_rmb` between the sequence and the data and
  between the data and the re-read, and arm64 reorders plain loads. BPF has no barrier instruction, but an atomic
  with `BPF_FETCH` is fully ordered (the arm64 JIT emits `ldaddal`, or an exclusive pair and `dmb ish` without LSE;
  x86 `lock xadd`), so `tego_dir_fence`, a fetch-add on the walk's stack whose result is kept (an unused result makes
  clang emit the relaxed, non-fetch add), follows each level's sequence read and precedes the second pass. It is
  sound wherever the plane runs (the fetch atomics are 5.12+; the plane needs `bpf_loop`, 5.17+), so no kernel or
  architecture falls back for want of it. A disconnected dentry, or a namespace root short of the task's root, is
  `UNREACHABLE`; more than 64 components, 8 mount crossings or 256 bytes is `LONG`. The sequences (whole 32-bit
  values, which no rename loop wraps while a preempted walk waits) and the mount pairs live in the task's storage
  (`struct tego_dir_scratch` in `tego_held`), since a walk's four frames share 512 bytes of stack (6.12 refused
  528); a task the storage cannot be made for is not walked. Any of these leaves `dir` empty and userspace names the
  side as before: the index where it holds the directory, else the marked `dev:ino/name` with a `dir-unresolved`
  gap. The walk is a global subprogram over `bpf_loop` in both builds (`tracerd` reads through `bpf_rdonly_cast`,
  `trace` through probe reads, and dead-codes the walk where the kernel has no `bpf_loop`, which no plane mode
  lacks), verified once per program: a static one, verified per call site, took rename, link and mknod past the
  verifier's million instructions on 6.12 and 6.17 once the mount pairs were checked. A global subprogram cannot take
  the record (6.17's verifier refused ring-buffer memory as its argument, `Caller passes invalid args`), so it builds
  the path in the task's storage and the caller copies it; its counters start from its argument zero, which the
  verifier does not know (the 6.1 verifier's once-verified callback, §2.7).
- **Userspace.** `observe.resolveFSOpPath` joins a walked `Dir` with the final component and matches the full path
  against the entries, as an open's `bpf_d_path` string is; the verdict stays the chain's return and the rule the
  plane's `rule_idx` on a plane refusal (T9), the model's on a Landlock refusal, and the entry whose grant allowed it
  on an allow (`grantName`, compile --test's name). An end outside every entry, which only a walked path names, is
  the inherited ruleset's refusal, unmatched, as `handleOpen` answers a write-open there (the model had called it
  `observed`: the conformance runner found it in lsm mode, where Landlock refuses before the plane runs). The supervisor's naming (`ContinuedFS`) is asked only for a side
  the kernel did not walk.
- **The gate, open.** `observe.Recorder` implements `runtime.PathHookNamer`, so a plane run's filter is narrowed
  (`usePlaneFilter`). Under `record: full` the open family (the write arm, `creat`) stays notified, since a full
  filter notifies every open, and the other mutations are left to the plane (T16 kept all of them there); so the
  conformance runner, whose fixtures are `record: full`, runs with the drop.

Tests. Unit (fail-first: the walked path ignored, every line read the supervisor's or `dev:ino/name`): observe
`TestRecorderNamesWalkedPathHooks` (allowed unlink, mkdir, rename within and across directories under the write
entry's rule; the refused `mv .git` under its `deny_write` rule; a raced walk marked, never a path; the supervisor's
naming never asked for a walked side), `TestDirPath`, `TestDecodeWalkedFSOp`; bpf `TestStructSizes` and the field
parity; landlock `TestPlaneFilterDropsOnlyWhatLoadedHooksDecide`, `TestHandlePlaneFilter` for `record: full`. Root:
cgroup `TestPlaneRunDropsAndNamesByPath` (fail-first on T16's recorder: the lines read `dev:ino/name`), a `record:
summary` run in each plane mode that checks the launcher logged the narrowed filter and holds each allowed unlink,
rmdir, mkdir, rename, symlink, link and truncate in a subdirectory of the write entry, the refused `mv .git` and a
refused mkdir outside every entry, to one kernel line each named by its full path and rule (§2.13 measured the
failure it guards: `26:17/.git` under `unmatched`); below Landlock ABI 3, where the filter's errno arm
refuses truncate(2) before any hook, the kernel's ABI (not the result) says so, and the run checks that refusal
(`EPERM`) in place of the truncate line.

**The stress cell (built 2026-10-06).** The tests above meet the walk with one renamer and one mount mover;
`TestPlaneSeqcountStress` (root, `-tags integration,tegobpf`, held by `test/vm/root-must-pass.txt`) is the cell for its
ordering, in each plane mode. The agent churns a leaf directory through a descriptor it holds, on several threads, so
that every mkdir, rmdir, create, unlink and symlink is decided by the plane and recorded with a walk of the leaf's
path, and every few turns attempts what the contract denies (a read, a mkdir and an unlink in the denied tree, a rename
and a link out of it, a write outside every entry). Meanwhile the test, outside the run, flips the directories above
the leaf in a fixed cycle (`stressChain`): two positions are renamed where they are, and two are one rename that moves
a directory between two parents and changes its name, so a walk that read its parent before the rename and its name
after it names a directory that never existed. The cycle visits eight of the sixteen spellings the chain can have, and
every line the ledger carries under the chain is one of three things: named by a path the leaf had, marked
`dev:ino/name` (the walk found a sequence moved, which fails closed), or wrong, which fails the cell. No denied action
may succeed, in the agent's own count or on the ledger, while the renames go on. That is not an ordering: the plane's
decision walk reads no sequence. The denied tree is not among the renamed directories, so its refusals come from rows
the walk meets before any ancestor, and the cell asserts that the load and the renames beside it never turn one into
an allow; the walks of the allowed actions do climb the renamed chain to the write entry's row above it, and a torn
climb could only refuse them (`refused_in_chain`, which the control run holds at zero), as TIER3-PLAN §8 argues for an
ancestor renamed during the unlocked `d_parent` walk. A control run of the same agent with the chain at rest must mark
no walk and refuse nothing under the chain, which is what makes the churn run's marked walks races. Each run prints one
`SEQCOUNT-STRESS` line with its counts, and the churn is 6 s on x86 and 30 s where loads are reordered
(`TEGO_STRESS_SECONDS` sets it for a run of the test binary). Guest runs of 2026-10-06, 6 s of churn,
`test/vm/root-suites.sh` shaped as a hosted runner's (`VM_CGROUP=service`, no lockdown, the 2560M this package's guests
need). On 6.17.0-41-generic, amd64: on the `lsm=...,bpf` boot, lsm mode named 389,230 of 408,579 ledger lines by a path
the leaf had and marked 2,699, none wrong, in 132,724 flips, and fmod_ret mode named 420,352 of 441,279 and marked
2,972, none wrong, in 136,179; on the kernel's own list, fmod_ret mode named 339,653 of 357,077 and marked 2,634, none
wrong, in 128,611. On AL2023's 6.1, the walk's other build (probe reads: the kernel's BTF has no `bpf_rdonly_cast`),
lsm mode named 477,964 of 507,020 and marked 8,031, and fmod_ret mode 381,864 of 406,688 and marked 7,943, none wrong,
in 153,489 and 144,072 flips. The control runs named 137,882 to 231,041 lines and marked none, and refused none under
the chain. In every run each of the agent's 4,217 to 17,668 attempts at what the contract denies was refused. On arm64
it has not run: `ci.yml`'s `build-test-arm64` runs it there from 2026-10-06 (R28), and that job's log is the
result. Its oracle and its agent are unit-tested without root (`TestStressChainCyclesThroughEightStates`,
`TestStressChainRenamesMatchTheModel` against a real tree, `TestStressChainATornReadNamesNoState`,
`TestStressTallyReadsLedgerLines`, and `TestStressAgentRunsItsCalls`, which runs the agent where nothing enforces), and
the tests were shown to catch a model whose pair flip leaves the name alone, an oracle that never calls a path wrong,
a cycle through all sixteen states and an agent that reads a file that is not there. The cell has not been shown to
fail against a walk with its second-pass compare removed: that needs a scratch build of `trace_proc.bpf.c` with the
compare taken out, and is the way to see it fail.

Guest runs, 2026-09-30, each from an archive of the commit (`test/vm/root-suites.sh`, both builds):
- **6.17, lsm=...,bpf** (`tracerd`): `internal/bpf` and `internal/runtime/observe` pass (`TestObjectsLoadOnThisKernel`
  loads every fsop program with the walk). cgroup `TestPlaneRunDropsAndNamesByPath` (lsm, fmod_ret),
  `TestPlaneRunEndToEnd` (lsm, fmod_ret, fanotify; its `record: full` contract now runs with the drop) and
  `TestTierBPFLSMRunEndToEnd` pass. `TestConformanceKernel` passes with nothing beyond its baseline
  (`exec-unlisted-script`): every fs, link and deny_write cell is one line with compile --test's verdict and rule at
  `cgroup@lsm` and `cgroup@fmod_ret`. Before the outside-every-entry fix it failed three cells at `cgroup@lsm`
  (`create-outside-every-entry`, `rename-into-write-entry`, `rename-out-of-write-entry` read `observed`), the fix's
  fail-first. One run also missed the kernel exec line of `exec-symlink-to-granted` at `cgroup@lsm`; the rerun did
  not, and no exec path changed here.
- **6.17 without bpf** (`TEGO_VM_LSM=kernel`, fmod_ret only): the same cgroup tests and `TestConformanceKernel` pass.
- **AL2023 6.1** (`trace`, the probe-read build): `internal/bpf` and `internal/runtime/observe` pass;
  `TestPlaneRunDropsAndNamesByPath` passes in both modes. `TestConformanceKernel`'s fs cells agree but for the two
  truncate cells, refused EPERM at every tier, `landlock` included (Landlock ABI 2: the filter's errno arm), and
  `TestPlaneRunEndToEnd` and `TestTierBPFLSMRunEndToEnd` fail on their setfacl cell, which wants `op: chmod` from
  `inode_set_acl` (6.2+) and gets the `inode_setxattr` sample: neither is this change's.

Stated as conditions:
1. *Closed 2026-09-30 (amended 2026-10-06):* a mount moved while a walk reads it. `d_path` reads `mount_lock`, which
   is no BTF symbol a program can read, so each crossing's parent mount and mountpoint are read again on the second
   pass (above) and a `mount --move` in the microseconds of a walk is `RACED`; this condition said it was not
   detected. Held, as root, by cgroup `TestPlaneRunNamesTrueUnderRenamesAndMountMoves` (about 7,000 mount moves and
   a rename loop over three seconds: every line names a path the directory had, or is marked).
2. *Closed 2026-09-30 (amended 2026-10-06):* the sequence reads are unordered. `read_seqcount_begin` has `smp_rmb`
   and a BPF program has no barrier instruction; `tego_dir_fence` orders the reads with a fetch atomic instead
   (above). Held by internal/bpf `TestDirWalkFencesItsSequenceReads` (both builds' compiled walk carries a fetch
   atomic in the step and before the second pass; fail-first: neither had one) and, as root, by cgroup
   `TestPlaneSeqcountStress` (below). x86's loads are not reordered, so the fence is checked in the object and only
   confirmed by a run there; arm64 is where it matters and where no run had been made, and CI's `build-test-arm64`
   runs the cell there as root from 2026-10-06 (R28). Its first log is the measurement, and is not yet recorded.
3. **The plane's own samples** (the attribute hooks, §2.12, and step C's mapping hooks, §2.14) are not fsop records
   and carry no walked directory: they are named by the index or `dev:ino/name` as before. Their syscalls stay
   notified or are no fs mutation, so the drop does not reach them.
4. **§2.13's conditions 2 and 3 stand**: the exec hand-over is not built, and kill test 4's pip contract fails
   Prepare at the plane tiers on Ubuntu 25.10's multi-call coreutils (the timing below replaced the two names with
   their directory, as §2.13's did).
   *Amended 2026-10-06:* both are closed. The exec hand-over is built (§2.19, 2026-10-04), and the
   multi-call coreutils was fixed on 2026-09-30 by exec rows keyed per link (§2.13's condition 3, §6 E15).

Kill test 4 pip with the drop on (`record: summary`), `debian-13` guest (6.12, bpf in the default LSM list, so tier
cgroup runs in lsm mode), 20 runs, `VM_ONLY=kt4 VM_KT4_TOOLS=1`, baseline / under tego medians / budget in ms:
- the first walk, the contract's `dirname` and `mkdir` replaced by their directory as in §2.13: cgroup 19/20,
  5373 / 6343 / 10746 (1.18x); bpflsm 20/20, 4398 / 5561 / 8796 (1.26x); load average 23.4 to 14.0.
- the fenced walk with the mount recheck, the contract as shipped (`dirname` and `mkdir` named, links of one uutils
  binary; `kt4-ordinary.sh` no longer swaps in their directory): cgroup 19/20, 3256 / 2791 / 6512; bpflsm 20/20,
  5789 / 2689 / 11578; load average 4.3 to 14.8. The baselines moved more than the runs under tego did, on a host
  shared with other jobs' guests: a direction, no more. The walk costs two passes of `bpf_loop` per recorded
  mutation, not per open.

Guest runs of the fenced walk (enforce-plane conditions 1 and 2 closed), each from an archive of the commit: 6.17
lsm=...,bpf and without bpf, and AL2023 6.1, as above: `TestObjectsLoadOnThisKernel` loads every fsop program on
6.1, 6.12 and 6.17; `TestPlaneRunNamesTrueUnderRenamesAndMountMoves` passes in every mode (93k to 169k lines named
by path under about 7000 mount moves and a rename loop, none marked, none wrong); the drop, end-to-end, tier `bpflsm`
and conformance cells as before, AL2023's two older failures included. internal/bpf `TestPlaneStepCHooksDecide`
fails on 6.17 and 6.1 in its exec-file-entry cells (rule 40 for 42): step C's, which no part of this change touches.

### 2.16 Moved

The measured section once numbered 2.16 is now §2.18.

### 2.17 Built at T9b (the record fallback: `decide.bpf.c`, `decide_stepb.h`, `enforce/cgroup` plane.go, `observe`)

TIER3-PLAN T9b makes R23's "never zero, never two" hold where the recorder's fexit on a hook the plane decides is not
attached. Before it, only `bprm_check` and step B's attribute and socket hooks wrote the plane's own sample; a refusal
on `file_open`, a path hook or a truncate had its one line from the recorder's fexit alone, and none without it.

- **How the plane learns (the mask).** `tego_plane_recorded`, a one-entry ARRAY in the plane's object pinned by name
  in the mode's directory, holds a mask of `1 << enum tego_plane_hook`: bit set, the build's recorder fexit on that
  hook's `security_` function is attached. tier cgroup's backend writes it in `newBPFPlane` from the tracing links the
  build holds (`recordedMask` over `bpfKernel.shared`, `bpf.PlaneRecordedMask` over `bpf.PlaneFexitPrograms`), after
  the object is loaded or adopted and before any plane program is attached, so no refusal of the build runs against
  a mask it has not written. Every launcher of the build writes the same value (the links are the build's, pinned).
  A mask nobody wrote is 0, so a plane loaded by anything else (doctor's probe, a test) samples every refusal:
  fail-closed for the ledger, since a missing line is the failure R23 forbids and a second one is visible.
  A per-build map rather than a `.rodata` constant, because the value is the build's links' and a program pinned
  with a constant would keep the first launcher's; rather than a field of `tego_run`, because that struct is
  tier 2's run-set value of every object and 12 bytes with no padding.
- **Hot-path cost.** None on an allow: the mask is looked up only on a refusal, after the decision, as the last step
  before `return -EACCES` (`tego_plane_fallback`). With the fexit attached the refusal costs one ARRAY lookup more.
- **The sample.** `tego_plane_fallback(run, hook, dentry, rule, reason, flags)` writes `struct tego_ev_plane` as
  `TEGO_EV_PLANE_FS` (23) through `tego_plane_own_sample` (moved from `decide_stepb.h` into `decide.bpf.c`, which the
  attribute, socket and mapping samples share): the object's directory `(dev, dir_ino)`, its final component read through the
  build's reader, the plane's rule and reason, the hook, and `file_open`'s `f_flags` in the former `pad2`, now
  `flags` (layout unchanged). Every refusal path of the ten hooks a fexit wraps calls it, the scratch value that
  could not be had included: `file_open`, `path_rename` and `path_link` in their bodies, `path_unlink` and
  `path_rmdir`, `path_mknod`, `path_mkdir`, `path_symlink` and the two truncates in `tego_modify_hook`, their one
  modification decision, each with its own refusal reason. A rename and a link name their source (`old_dentry`), as the recorder's line
  names it first. The plane's decision still goes to the scratch value, so an attached fexit takes it as before.
- **The line.** observe's `handlePlaneFS` names the sample as the fexit's line would have been named: the operation
  its hook stands for (`planeFSKinds`: an rmdir the unlink, a mknod the open with `O_CREAT`, both truncate hooks the
  truncate), the plane's rule and reason by `planeFS` (so `compile --test`'s bpflsm column names it alike),
  mechanism plane, the mode, `plane_reason`; the file through the rule table's directory index, as an attribute
  change's is. It is kept under `record: off` (a refusal).
- **Verified instructions** (6.17 guest, probe-read build / rdonly build, LSM mode; fmod_ret within 20): `file_open`
  2,874 / 4,527, `path_rename` 2,959 / 4,778, `path_unlink` and `path_rmdir` 2,718 / 4,535, the creates 2,719 /
  4,536, `file_truncate` 2,802 / 4,604 (from 1,048 / 3,924 for `file_open`: the sample is verified on the refusal
  path of each hook).
- **Kernels** (root suites in the KVM guest, `VM_RUN=Plane` over internal/bpf, observe, enforce/cgroup and doctor): 6.17
  with `bpf` in `lsm=` (both modes, both trace builds) and on its default boot (fmod_ret); AL2023's 6.1 (the probe
  builds, both modes). `TestPlaneRunEndToEnd`'s setfacl cell on 6.1 expected op chmod, which 6.1 writes as op xattr
  (`inode_setxattr`, no `inode_set_acl`): the cell now takes either, a T13 expectation the first 6.1 run of it found.
- **Tests.** `bpf/tests` `TestPlaneFallbackOnEveryFexitHookRefusal` (every refusal path of the ten hooks calls the
  fallback, the fallback samples exactly where the mask's bit is clear, the mask is pinned by name, the hook list is
  `bpf.PlaneFexitPrograms`); `internal/bpf` `TestPlaneRecordedMask`, the pairing and kind tests, `PlaneEvent.Flags`'
  layout parity; `cgroup` `TestRecordedMaskIsTheAttachedFexits`; observe `TestRecorderNamesPlaneFallbackSamples`
  (every hook, both record modes, rule and reason against `decide.PlaneEvaluator`), `TestPlaneFSKindCoversTheFexitHooks`,
  `TestDecodePlaneFS`; and the root `TestIntegrationPlaneFallbackIsOneLine` in the guest, both trace builds, each mode,
  `record: full` and `off`: trace_proc loaded with none of its ten fexit programs attached and the mask 0, a refused
  read, a rename out of `deny_read`, `mv .git`, a link out of it, an unlink, an rmdir, a write-open outside every
  entry, an `O_CREAT` open, a mkdir, a symlink, a truncate and an ftruncate are each exactly one fs line (the plane's
  sample) with the rule and reason the bpflsm column gives, and the unlisted exec one exec line. Fail-first: with the
  mask saying every fexit is attached (what the plane did before T9b), the same cell had 0 fs lines for the 12
  refused fs actions. `TestIntegrationPlaneRefusalIsOneLine` now writes the mask the backend would (every fexit
  attached) and still has one line per action.

Found here, stated as conditions:
1. **A partly attached recorder.** The backend attaches every trace program or fails Prepare, and an optional fexit
   (`security_file_truncate` below 6.2) is absent exactly where the plane's hook is, so a build is all-or-nothing
   today. Were one fexit missing beside another that is attached, an `O_TRUNC` open whose truncate the plane refuses
   would have the open fexit's held record flushed as its own line beside the plane's truncate sample (the hold
   waits for the truncate fexit that never runs): two lines for one action.
2. **The fallback line's path.** The plane has no `bpf_d_path`, so `file_open`'s sample is named through the
   directory index like a file operation's: an open in a directory no fs entry names carries the raw `dev:ino/name`
   identifier and a `dir-unresolved` gap (a truncated name has only its `path-truncated` gap; the recorder's own open line has the whole path).
3. **A rename or a link names one end.** The sample carries the source only; the destination the fexit's line
   carries as `path2` is absent.
4. **A detached link is not noticed.** The mask is the links the build held when its plane was set up; root outside
   the run detaching a recorder link afterwards (§9) leaves the bit set, and that hook's refusals without a line.

### 2.18 Measured 2026-09-30 (tier-3 performance: a run's start and an open's cost at the plane tiers)

*Restored 2026-10-06:* this section was dropped by mistake on 2026-09-30 while `bpf/include/maps.h`, TIER3-PLAN §9 and §10 and
limits-check-doctor-cli R27 still cite it; it is the 2026-09-30 text unchanged. The run-probe cache's entry format
has moved on since (§2.5).

Profiled in the 6.17 guest with `bpf` in lsm= (4 vCPUs, 1.5 GiB, host load average 17-37 from other jobs' guests),
`tego run --tier <t> -- /bin/true` under `base/python-dev` plus a write entry, a CPU profile and a Go execution
trace per run, and `kernel.bpf_stats_enabled=1` for each program's `run_time_ns`.

- **A run's start was the plane's load, every run.** 0.59 s of a 0.95 s start at tier `bpflsm` was
  `BPF_PROG_LOAD` under `newBPFPlane`: every run loaded and verified the mode's programs again. `adoptObjectIn`
  adopts an object's pinned programs only when every map it declares, but its global-variable sections, is pinned
  by name, and `tego_plane_path_buf` (the refused exec's name buffer) was not, so no launcher after the
  first ever adopted the plane. It is pinned by name now; `TestAdoptedObjectsPinEveryMapByName` holds every map of
  every adopted object to that (fail-first: it named the buffer in both builds), and the root
  `TestPlaneRunAdoptsThePinnedPlane` holds a second run to the first run's program ids.
- **The rest of the start was parsing the kernel's BTF** (50-100 ms of CPU a run: `kernelHasFunc` for the optional
  hooks and tracing program, `KernelReader`, D2 with the objects' CO-RE needs, and cilium/ebpf's name index). The
  answers cannot change within a boot: doctor's run-probe cache (format 6) keeps D2's answer and whether the BTF
  has each of `bpf.KernelFuncNames`, and a run that reads a valid entry takes D2 from it and seeds its loaders
  (`bpf.SeedKernelFuncs`, consulted by `bpf.KernelHasFunc` and `KernelReader`), so an adopting run parses no BTF
  (`TestRunAtReachCgroupReadsTheCacheAsRoot`, `TestKernelHasFuncAnswersFromTheSeedWithoutParsing`,
  `TestSeededReaderIsTheParsedOne`). A name the seed lacks is parsed for as before, and a BTF that cannot be read
  still answers yes, so the load names the missing function: no answer changes, only where it comes from.
- **Start, before / after, ms, runs 2-10 of 10, same boot:** tier `cgroup` (lsm mode) 1713-3125 / 130-607; tier
  `bpflsm` 1199-2381 / 158-292. After, a run's CPU is about 90 ms (the embedded objects' ELF parse 19 ms, GC 14 ms,
  `bpf_hash` 7 ms) and its main goroutine blocks in syscalls for 29 ms; the rest is the loaded host's scheduling.
- **Below 6.7 the rest was grace periods.** On AL2023's 6.1 an adopting run still took 490-640 ms, 440 ms of it in
  `BPF_MAP_LOOKUP_ELEM` on the map-of-maps outers: every userspace lookup of one ends in `synchronize_rcu` there
  (`bpf_map_copy_value`'s `maybe_wait_bpf_programs`, gone from 6.7 with upstream 2a0c6b41eec9), and a start made
  about nine (`RingOf` in `slotRings`, `drainRing`, the recorder and the uprobe source; `prepareSlot`; `innerOf`).
  `bpf.InnerIDs` reads an outer in one `BPF_MAP_LOOKUP_BATCH`, whose hash-table path returns each inner map's id with
  no wait, and walks key by key only where a batch fails; every one of those reads goes through it
  (`TestInnerIDsReadTheOuterByBatch`, which fails where the kernel would fall back). AL2023 6.1, same boot, runs 2-10:
  tier `cgroup` 486-592 / 91-154 ms, tier `bpflsm` 520-637 / 112-177 ms. An insert or removal in an outer (a ring
  placed or trimmed, a slot's first row maps) still waits a grace period there; none is on an adopting run's path.

- **An open's cost.** Per `open(2)+close(2)` of a 20,000-open loop inside a run, best of five, and each program's
  mean from `run_time_ns`, on the same boot: bare 2.4-3.7 µs; tier `landlock` adds 1.6-1.8 µs (Landlock's walk and
  the seccomp filter, the floor every tier keeps); the plane's `file_open` costs 0.28 µs for `/etc/hostname` (3
  levels, no row) and 0.79 µs twelve levels down under a write entry (about 50 ns a level: one hash lookup and three
  reads); the recorder's `fexit/security_file_open` costs 0.51 and 1.13 µs (`bpf_d_path` grows with the depth, then
  the ring's reserve and submit). The supervisor does nothing per open at the plane tiers under `record: summary`:
  read-opens were never notified (enforce-landlock R12) and the write arm is the plane's (§2.13). Under
  `record: full` every open is still notified (enforce-landlock R16: its notification is the record of a read), which
  the plane does not change. The 2 µs budget (TIER3-PLAN §9) is not met by the plane alone: the floor and the
  recorder's read record, both kept at every tier, are 2.1-2.9 µs of it before the plane's walk, and dropping either
  would change what is enforced or recorded. The plane's own share is 0.3-0.8 µs on 6.17's rdonly build; on
  AL2023's 6.1, whose probe-read build reads each level through `bpf_probe_read_kernel`, it is 0.7 µs at three levels
  and 1.8-2.3 µs at twelve, and the recorder's 1.1 and 2.3-2.9 µs.

Kill test 4, 20 runs, `VM_ONLY=kt4 VM_KT4_TOOLS=1 VM_KT4_TIERS="cgroup bpflsm"` (`VM_ONLY_LSM` adds `bpf` to the host
row's lsm=), baseline / under tego medians / budget in ms. Before (T11's figures, the tree before these changes): go
at tier `cgroup` (lsm mode) 147 / 315, at `bpflsm` 238 / 485, both over 2x. After, with the plane adopted and the BTF
answers cached (the batch lookups not yet in), host load average 3 to 7:
- **6.17, lsm=...,bpf:** go `cgroup` 20/20, 142 / 216 / 284 (1.52x); go `bpflsm` 20/20, 138 / 218 / 276 (1.58x); npm
  20/20 at both (498 / 575, 498 / 553); pip 19/20 at `cgroup` (2585 / 2316; its one broken run is the build's first,
  which loads every program, 11.2 s) and 20/20 at `bpflsm` (2082 / 2275).
- **6.17, the kernel's own lsm= (fmod_ret; no tier `bpflsm`):** go `cgroup` 20/20, 159 / 217 / 318 (1.36x); npm 20/20;
  pip 19/20 (the first run again).
- **AL2023 6.1, before the batch lookups:** go 0/20 at both tiers (113 / 701, 192 / 738) and npm 0/20: the 440 ms of
  grace periods above. With them, at load 6-9 (other jobs' guests): go `cgroup` 19/20, 201 / 330 / 402 (1.64x);
  go `bpflsm` 392 / 604 median (1.54x), stopped at 5 of 20 by two runs of 966 and 995 ms; npm 20/20 at both; pip 19/20
  at `cgroup`, 18/20 at `bpflsm` (two runs 1% and 21% over). Repeated on 6.17 at load 8-19, every kind's baseline
  moved by 2x between runs of one boot (go 138 to 337 ms, pip 2.1 to 6.8 s) and a run's wall with it; a verdict there
  is the host's, not tego's.
- **All three, on the current tree, load 10-30:** 6.17 go `cgroup` 20/20 (348 / 510, 1.47x), go `bpflsm` 20/20
  (255 / 321, 1.26x), pip 19/20 and 20/20, npm 20/20 at `bpflsm` and 0/20 at `cgroup` (728 / 1488 against 1456, the
  first run 2 ms over); AL2023 go `cgroup` 7/20 (242 / 464, 1.92x), go `bpflsm` 1/20 (150 / 349, 2.33x), npm 20/20 at
  both, pip 20/20 at `bpflsm` and 6/20 at `cgroup`.

Stated as conditions:
1. **The 2 µs open budget is not met** at the plane tiers (above): the floor and the recorder's read record cost more
   than it before the plane decides anything. Meeting it needs the record of reads to change (for example, reads
   under a matched entry counted in the kernel rather than named by `bpf_d_path` and sent through the ring), a
   decision of the record's semantics (SEMANTICS §7, R13), not of the plane.
2. **Kill test 4 go holds its 2x bound with about 60-80 ms to spare** on a quiet host: a run's start is now about
   80-150 ms (90 ms of CPU: the objects' ELF parse, `bpf_hash`, GC) against go's 140 ms. On a loaded host the start
   stretches with the load and single runs cross the bound. On AL2023's 6.1 go's excess stays about 130-200 ms (its
   probe-read build costs 2-3x 6.17's per open, above), so there it holds only on a quiet host.
3. **The root suites.** At first `internal/bpf` `TestPlaneStepCHooksDecide` failed on both kernels
   (its objects load unpinned, so the pinning here does not reach it) and, on AL2023, `TestPlaneRunEndToEnd` and
   `TestTierBPFLSMRunEndToEnd`'s setfacl cell (§2.15); after the later fixes, every suite this
   change touches passes on 6.17 with `bpf` in lsm= and on AL2023 6.1 (`internal/bpf`, `enforce/cgroup` and
   `internal/doctor`, both builds, and `tego doctor` as root).

### 2.19 Built 2026-10-04: complete exec handover and outcome recording

Exec notifications remain as bounded metadata capture under `ID_VALID`; they no longer decide policy when the kernel plane, both pinned `sys_exit_execve`/`sys_exit_execveat` hooks, naming callback and live recorder are ready. The supervisor captures original TID, process birth, monotonic attempt timestamp, cwd identity and attempted argv before CONTINUE. A fixed ring retains consumed/unreadable ownership markers so delayed outcomes cannot borrow the previous attempt's metadata. If recording fails, supervisor ownership resumes; its attempt marker suppresses duplicates from a final ring drain.

`sched_process_exec` records success with `old_pid` for non-leader execs. Negative syscall returns record failures outside policy hooks too (`ENOENT`, `ENOEXEC`, `ETXTBSY`). Kernel-private `__FMODE_EXEC` in `f_flags` identifies early image opens; opened-path and bprm fragments are joined only within the proven attempt interval. Refusals folded into an exec have one terminal exec line; allowed image opens retain filesystem full/watch/aggregate recording. Kernel plane decisions retain their rule/reason, while an unexplained error stays observed. Actual syscall returns and argv provenance are additive ledger v1 fields at `record_minor` 3; the separately versioned BPF ring ABI is 3.

Successful mapped argv is authoritative. Metadata can extend a matching truncated prefix only with explicit provenance and retained truncation. The kernel's binfmt interpreter marker, actual first opened image and exact mapped argument tail preserve declared script-based MCP starts without accepting a native argv forgery. Raw pathname and cwd identity must both agree before an absolute metadata spelling replaces a relative kernel name. Missing proof produces a gap. Optional tracepoint links that cannot be pinned keep supervisor ownership and do not prevent adoption of the remaining trace object.

The guest regressions passed on Linux 6.17 in cgroup LSM, cgroup fmod_ret and bpflsm LSM modes: `TestPlaneRunExecOutcomes` covers repeated refusals, missing images, invalid formats, busy images, non-leader success and record off; `TestPlaneRunExecEntryPrecedence` covers overlapping directory/file/name grants. `TestPlaneRunBtrfsSubvolumeInodeIdentity` proves repeated inode numbers across subvolumes retain distinct kernel pointer rows and agree with compile/model/ledger outcomes. *Amended 2026-10-05:* that btrfs pass was a hand-provisioned guest; no gate ran the test, which skipped without btrfs-progs and whose skip root-skips.txt allowed. It now mounts an embedded empty btrfs and needs only the kernel's btrfs, which root-suites.sh's guests load by default (`VM_MODULES`), and its skip is allowed in the plain build only (an `untagged:` entry, as for the other plane runs), so a skip in any root run of the tegobpf suite (`make vm-root-test`, CI's root-suites job, vm-matrix's tier-3 step) fails that run. These tests establish their exercised cases; earlier performance and matrix measurements remain dated evidence until rerun.

### 2.20 Built 2026-10-04: listener admission and the process controls (`bpf/decide_socket.h`, `decide_listen.h`, `decide_control.h`)

Written 2026-10-05 from the code; `bpf.PlaneHooks` holds 28 hooks, the six below after step C's. Each is a decided
hook under R1 to R3, in both modes, probed by doctor with one refused action each
(`planeControlAction` in `internal/doctor/planeprobe_control.go`), and returns 0 for a task in no run or in a run of the other mode.

- `socket_bind` decides AF_UNIX addresses only; any other family returns 0 (the cgroup `bind4`/`bind6` programs decide
  inet binds). The run is the current task's for an AF_UNIX socket, or the socket's creator cgroup's for a
  supervisor relay. A slot with no header of the run's gen refuses (R6); a header without `TEGO_SLOT_LISTEN_DECIDES`
  (no `net.listen`) returns 0. It writes the listener marker into the task's scratch; with no scratch value it
  refuses and counts `unresolved`. An autobind (`addrlen <= 2`) or an oversized address is refused
  (`net-not-allowed`). An abstract name is looked up in the slot's `tego_plane_listen_rows`: no row of the run's
  gen refuses (`net-not-allowed`), and no inner map refuses (`path-unresolved`, counted `norows`). A pathname is
  decided at `path_mknod`, against the row keyed by the created node's resolved parent inode and basename, whose
  parent identity (`i_ino`, `i_generation`, `s_dev`) must match (`identity-mismatch` otherwise).
- `socket_listen` decides AF_UNIX, AF_INET and AF_INET6 sockets under `TEGO_SLOT_LISTEN_DECIDES`, with the same run
  and header rules. A Unix socket's bound dentry or abstract name must have a listen row; an unbound one is refused.
  An inet socket must be TCP; one whose successful explicit bind left a `tego_net_binds` row passes, and otherwise
  its bound address and port need an allow row in `tego_bind_exact` (exact, then the family's wildcard address). An
  absent or other-gen `tego_net_control` row refuses.
- Records: a Unix bind or listen decision is carried by the marker to its one terminal line, written with the
  actual return by `sys_exit_bind`/`sys_exit_listen` (`tego_listener_result_emit`), which also clears the marker.
  These programs use the individual syscall event's `syscall_trace_exit` context, retaining CO-RE (not
  `raw_syscalls`' `trace_event_raw_sys_exit`, whose return offset differs on RHEL 9; ADR 0024's 2026-11-05 correction).
  The loader and doctor require tracefs's `ret` field at offset 16, size 8, matching the supported BPF syscall
  exit wrapper; an unknown or divergent format refuses the hook before loading or adoption, with the reason. A
  refused inet listen writes the plane's own `TEGO_EV_PLANE_SOCKET` sample; a supervisor relay's line is its
  completion's. *Amended 2026-10-05:* io_uring's `IORING_OP_BIND` and `IORING_OP_LISTEN` (6.11+) reach both hooks
  through `__sys_bind_socket`/`__sys_listen_socket` with no bind or listen syscall exit, so their refusals had no
  line and the marker outlived the op: the same task's next `mknod(S_IFSOCK)` was judged as a listener bind and
  refused, unrecorded. fexit programs on `io_bind` and `io_listen` (`tego_uring_bind_result`,
  `tego_uring_listen_result`, trace_proc) are now terminal producers too: they write a marked operation's line
  with the op's result (the completion's `res`), flagged `TEGO_BIND_URING` so the recorder expects no supervisor
  naming, and clear the marker. They are optional where the kernel lacks the functions (no such opcodes there) and
  loaded, and required, for a run with explicit listener control (`TestPlaneRunIOUringListenerOutcomes`,
  `TestURingListenerResultsNeedNoSupervisorNaming`).
- `ptrace_access_check` (ATTACH mode only; read-mode checks are left to the chain) and `ptrace_traceme` refuse
  unless the peer task, found by its default-hierarchy cgroup in `tego_run_set`, is in the same run and gen
  (`process-scope`); no slot header refuses (`path-unresolved`). `bpf` refuses every command of a governed task
  (`process-scope`). `key_permission` (Optional: left out where the kernel's BTF lacks its target) refuses unless the
  header carries `TEGO_SLOT_KEYRING_ALLOWED` (`keyring: true`; `read-denied`); no header refuses. Each writes the
  plane's own `TEGO_EV_PLANE_CONTROL` sample.
- Governed-run cells (2026-10-05). `plane_control_integration_test.go` runs the four process controls
  through `tego run`, in every plane mode the machine passes and at tier `bpflsm`, under `record: full` and `off`;
  `test/vm/root-suites.sh` runs it in the guest on both boots. Each refusal is a `refused` line from the kernel with
  `mechanism: plane`, `decision_plane` the mode and the agent's pid, and an allowed action leaves none. Where a hook
  sits behind another arm of the same run, the cell says which of the two answers. The conditions:
  - `ptrace_access_check` and `ptrace_traceme` (`TestPlaneRunControlPtraceIsRunScoped`). The agent attaches to a host
    process of its uid, to the agent of a second run, to two children of its own that root moved out of its cgroup (one
    to a cgroup in no run, one into the second run's) and to a child that stayed, then asks to be traced by a parent in
    the run and by its parent outside it, the launcher. The plane refuses the moved children and the launcher with
    EACCES and one line each (op `ptrace` or `ptrace_traceme`, rule `process-scope`, reason `landlock-topology`, the
    peer's pid), and allows the child that stayed and the parent in the run. Landlock's own ptrace scope, which every
    tier's domain carries (ARCHITECTURE §11), is in front of the ATTACH hook: where `bpf` follows `landlock` in the LSM
    list (as it does in `lsm` mode, since the `lsm=...,bpf` boot appends it), an attach out of the run to a task outside
    its Landlock hierarchy, here the host process and the second run's agent, is Landlock's EPERM and never reaches the
    plane, so it leaves no line; in `fmod_ret` mode, whose programs run before the whole chain, the same attach is the
    plane's EACCES with its line. The moved children are in the run's own domain, so Landlock admits them and only the
    plane refuses them, in both modes: that is the case the hook exists for, a peer found by its cgroup and never by
    its pid or its domain. `ptrace_traceme` is the plane's alone in both modes, since Landlock lets an unconfined
    parent trace a confined child. While the runs are live, a process of no run attaches, uses the keyring and makes a
    BPF map without being decided (R1).
  - `key_permission` (`TestPlaneRunControlKeyringIsTheContractsOptIn`). The hook is the contract's `keyring: true` and
    nothing finer: it admits every key permission check of a run whose header carries the flag, whichever key, and
    refuses every check of one that does not (`read-denied`). It is per check, not per syscall: `keyctl(GET_KEYRING_ID)`
    asks to search the keyring and `add_key` to write it, one check and so one line each (`permission 4` and
    `permission 3`, `enum key_need_perm`), where `keyctl(DESCRIBE)` makes three (the view, then two searches for an
    authorisation token) and leaves three lines for its one refusal. It is behind the supervisor's refusal of
    `add_key`, `request_key` and `keyctl`: a run without the opt-in sees EPERM and the supervisor's `refused`
    line (rule `keyring`, source `supervisor`) and no plane line; with it the supervisor continues the three syscalls,
    the plane admits them (the flag reached the header) and the use is the supervisor's `gap what=record
    why=keyring-<syscall>`. The plane's own refusal is reached only with the filter's arms left out (the seam below).
  - `bpf` (`TestPlaneRunControlBPFIsRefused`). The filter's root-tier arm answers every `bpf(2)` with EPERM before the
    kernel is asked (ADR 0033), so the hook is a second layer no product run reaches. The cell hands the agent a map
    descriptor over SCM_RIGHTS from outside every run and runs a lookup, an update and a get-next-key on it: commands
    that need no capability on a descriptor the caller holds, so `security_bpf` alone stands between the agent and the
    map. With the product filter each is EPERM and leaves no line; with the arm left out each is EACCES with one `bpf`
    line naming the command (`command N`) and the map is unchanged. `BPF_MAP_CREATE` is not a cell:
    `kernel.unprivileged_bpf_disabled` refuses it with EPERM ahead of the hook where it is set.
  - The seam. A build with `-tags tegotesthooks` reads `TEGO_TEST_FILTER_OMIT`, a comma-separated list of syscall
    names the seccomp filter leaves out of its notify arm and its root-tier arm (enforce-landlock R11); the cells name
    `bpf`, `add_key`, `request_key` and `keyctl`. In a product build the seam is a function that omits nothing.
  - Passed in the KVM guest on 2026-10-05: Linux 6.17 on the `lsm=...,bpf` boot (both plane modes and tier `bpflsm`)
    and on the default boot (`fmod_ret`), RHEL 9's 5.14 and AL2023's 6.1, both with `bpf` in their own LSM list.

### 2.21 Name entries (ADR 0043): the row model and the kernel built, the backend's rest not

ADR 0043 (amending ADR 0039) adds name entries to the plane: `RuleTable.NameDeny`, compiled from the built-in `.env`
list and from whole `deny_read` globs whose final component is a literal or a literal prefix, and `NameExempt`
(`pkg/spec/agent`). The first stage (2026-10-05) built the compiler, the root model and the row model in
`internal/policy/decide`; the second (2026-10-17) built the kernel half and the backend's fill of the name map. Every
piece waited on a build switch (`agent.NameEntriesEnforced`) until the last stage turned it on and removed it (2026-10-27,
ADR 0043 C11): a table with name entries now gets its scope and name rows, the header's flag and compaction everywhere.

- **Scope rows** (`planenames.go`): each scope directory gets bit *i* of `PlaneRows.Scopes` (sorted, at most 8) in the
  row at its path, which the kernel row's spare byte will carry. A scope directory no entry, target or exec grant
  keys is a `PlaneScopeOnly` row (kind bit 6): keyed, pinned and identity-checked like every row, read by the name
  check's climb alone, and **passed by the walk** (`PlaneRows.Find`), so it changes no answer and no walk bound. A
  complete row there instead would let a path more than 64 steps below its nearest entry resolve at the scope row,
  which `TestNameEntriesMonotonic` showed turns the root model's `path-unresolved` refusal into an allow.
- **Name rows** (`PlaneRows.NameRows`): one per folded literal and form, keyed by `agent.NameKey`, with arms: a deny
  arm per entry over its scopes' bits, an exception arm per built-in example name (cancels the prefix entry; the
  bytes after the prefix compare exactly), and a depth-1 exempt arm per D3 exemption over its parent's bit (cancels
  every entry). `Leads` and `PrefixLens` are what the slot header will carry. Caps (64 rows and entries, 8 arms,
  8 scopes, 4 prefix lengths, 8 leads) are `ErrPlaneNameCap` for a hand-built table; compile leaves out what does
  not fit.
- **The name check** (`PlaneRows.DecideObject`): after the walk allows a read, a modification or a rename of a file,
  the leads prefilter, the exact and prefix lookups confirmed by the folded compare, the arms, and the climb from the
  file's directory (scope bits met before a dependency directory, at most 64 levels; past them `path-unresolved`).
  A directory is never decided. D5 is `ScopeMoveRefused`, after REFER. The rule of a name refusal is
  `PlaneRuleName | scope bit << 6 | entry` in the kernel's u16 (`PlaneNameTag`, disjoint from fs rows, `0xffff`,
  `PlaneRuleFSRow` and the listener's bit) and names the entry's rule (ADR 0043 D8).
- **Compaction** (D6, `compactRows`): past `PlaneCompactAt` (1024) keyed paths, a per-file row whose file a name entry
  decides alike (regular, one link, no symlink, not a mount point, a filesystem with one spelling, no bind exposure,
  its walk without the row allowing both questions) is dropped, only as many as needed, in reverse path order; a
  dropped file's refusal names its own entry. `ErrPlaneCap.Compacted` says how many were dropped when the table
  still does not fit.
- **Parity** (R25): `TestPlaneRowsMatchEvaluate` and `TestPlaneEvaluatorMatchesEvaluate` run every generated table
  of up to two entries with five name dimensions against `Evaluate`, files and directories, renames included (a
  build with the race detector, which finds nothing in a sweep that starts no goroutine, checks every eleventh table:
  `sweepStride`);
  `TestPlaneCompactionIsVerdictNeutral`, `TestPlaneCompactionKeepsAliases`, `TestPlaneCompactionIsDeterministic`,
  `TestRecorderCompilesTheSameRows`, `TestCompactedTableFits` (4,500 `.env` files fit and stay refused) and
  `TestPlaneNameQueriesAllocateNothing` hold the rest. Measured on the development machine (i7-10870H, GOMAXPROCS=4): a name
  refusal 570 ns, 0 allocations (`BenchmarkPlaneDecideName`); compiling the 4,500-file table with compaction 8.7 ms
  against 17.7 ms for the cap table (`BenchmarkCompilePlaneCompaction`, `BenchmarkCompilePlaneScale/cap`).
- **The kernel** (2026-10-17; ADR 0043's implementation notes): a fourth per-slot inner map,
  `tego_plane_name_rows` (65 entries: 64 name rows and the config row at key 0), a 128-byte slot header carrying
  `TEGO_SLOT_NAME_DECIDES` and the prefilter's leads, the scope bit in `tego_plane_row.scope`, and the scope-only
  kind every walk passes. A name row holds its arms summed up (the entries it denies, a built-in exception's entries
  and literal length, D3's scope bits), so the kernel reads no arm. Under the flag, file_open (a file's read or
  modification), the create, unlink and truncate hooks (through `tego_modify_hook`), path_link (the new name, REFER's
  source) and path_rename (both ends of a file's rename, D5 for a directory's) ask the name entries where the walk
  allowed the question and the object is no directory, with one global call (`bpf/decide_names.h`):
  `tego_plane_name` reads the header again, takes a mount root's name from its mountpoint, runs the prefilter, then
  the global name check (keys, rows confirmed by the folded bytes, their summaries) and the global climb (scope bits
  to the deciding scope, dependency directories by name), one after the other; D5 is `tego_plane_move`, one direction
  a call, asked of each direction that moves a directory. A missing name map, config row or header refuses
  `path-unresolved` and counts `norows`; a climb that cannot decide refuses and counts `bound` or `unresolved`; on the
  probe-read build a name whose `hash_len`, address or bytes `bpf_probe_read_kernel` could not read refuses
  `path-unresolved` and counts `unresolved` (ADR 0043 D2's failure paths); a scope row whose identity is gone counts
  `mismatch`. Each hook's decision is read back through the task's scratch value before its record and fallback
  sample (`tego_plane_settle`), path_rename's destination is tested positive at run time (`tego_positive`: a
  verifier that holds a trusted dentry's `d_inode` never NULL hard-wires a plain test of it), path_mknod's socket-bind
  arm is a subprogram of its own that reads the floor from the task's record of the decision, and the fallback's
  sample is a global function, verified once per program, so every program the name entries touch stays inside the
  plane's budget of 20,000 verified instructions on every MATRIX row (`TestPlaneLoadsAndAttaches`, §2.3; ADR 0043's
  implementation notes have the figures per program, build and row, and the fixes the matrix asked for). The
  backend writes the map, the config row, the scope bytes and the header (`plane.go` `putNameEntries`: the map
  cleared, the config row, each name row with `BPF_NOEXIST`, before the header) for a table with name entries,
  every product build's since 2026-10-27 (the build switch `agent.NameEntriesEnforced` and its test hook are gone).
  Verified on the KVM matrix rows the implementation notes list.
- **Open condition: verification time.** ADR 0043's limit of 6 ms of verification a lsm program on 6.17 is not met,
  before the name entries or after: the base object's lsm programs verify in 3 to 99 ms in the 6.17 guest (23 to 25
  of either build's 28 over 6 ms, those no name entry touches included), and the name work adds 7 to 32 ms to the programs
  that ask names (path_rename the most) and takes 31 to 49 ms off path_mknod, on a busy host (ADR 0043's notes have
  every program's figures, and how path_rename's first 98 to 133 ms more came down: its objects' kinds are read back
  through the task's scratch value before its walks, so the verifier walks its chain once). The load test
  prints `BUDGET OVER` (test/perf's marker for a figure over its limit, never `TARGET-MISS`, which is a figure inside
  its limit) with the time for each program over the limit, and does not fail on it: an exception to ADR 0043's
  "Limits fail the run", which its Status line and index row disclose, rather than the matrix's main row failing for
  every package on a figure the base missed. The limit is not relaxed, and the miss stays open: a later change to the verifier cuts meets it, or an amendment moves it.
- **Clears** (2026-10-27): every clear of a slot (`bpfPlane.clearSlot`: Detach, Prepare's purge of a
  reclaimed slot, the reaper through the build's pinned planes, which `openPinnedPlanes` now opens with their name
  map) zeroes the header, runs the kernel's clear of the inode-keyed rows, then deletes the slot's name map entries from
  userspace (`clearNameRows`, at most 65 keys); the inner map stays in the outer, as the fs and exec inner maps do,
  since replacing it would cost a grace period below 6.7. A pinned plane whose name map pin is gone is not adopted: the
  next run loads the mode's programs over a new name map (`TestPlaneNameRowsFillAndClear`,
  `TestPlaneNameMapAdoption`).
- **The fallback's listener** (2026-10-27): tier 2's fanotify listener refuses an open of a covered
  file beneath the scopes it marks (enforce-cgroup-observe R8).
- **Not built**: the fallback supervisor's half (its mutation refusals, `decide.AdvisoryFS`'s
  tier-cgroup branch, and supervisor R15d's directory moves); the tier-2 recorder's naming of a listener's name refusal it
  infers; the plane recorder's naming of a compacted file by
  its path; doctor's cells; the capability `fs.deny_read.created_later`; compile's print; the conformance space; the
  performance budgets of ADR 0043.
- *Finding, not changed here:* a row the plane keys at a path that is not an entry's (a `deny_write` target's chain,
  an `exec.allow` directory, a watch entry's complete row) is met by the kernel's walk within 64 steps of a deeper
  path whose nearest deciding entry lies beyond them, and the walk answers from it, where the root model, counting
  steps to an entry, refuses `path-unresolved`. The bpflsm column follows the rows, so the divergence is between
  `compile --test`'s cgroup column and the plane, beyond 64 levels; the generated probes stay within the bound.

### 2.22 Exec pins (ADR 0048 (3) P2): built 2026-10-19; runs with command rules or an exec gate are pinned

ADR 0048 (3) P2 holds every exec of a pinned run to the facts the supervisor decided. K1 built the kernel half
(`bpf/decide_execpin.h`, `bpf/include/events.h` and `maps.h`), K2 and K3 Prepare's and the supervisor's halves
(`enforce/cgroup` `execpins.go`, `supervisor` `exec_pin.go`, `internal/execpin`), K4 the ledger's fold of the plane's
held and kill samples (`observe` `exec_pin.go`, ADR 0048 (8)). A run is pinned when its caller asks
(`cgroup.Run.ExecPin`): the runtime asks for every run whose table has command rules, or an exec gate that can
escalate (`agent` `RuleTable.ExecFactsDecided`). Prepare pins it only on a plane whose object has the pin maps and whose kernel
recorder has exec outcomes (the exec-result programs attached): a kill's line is the recorder's exec record folded with
the kill sample, so a kernel with no record of the run's execs would leave a kill without a line.

- **Prepare** (`fillPlane`, `putPins`). A run asked to be pinned, on a plane whose object has the pin maps, in a
  launcher whose time namespace adds no boottime offset to `/proc`'s start times (and whose children enter the same
  one), gets a 128-bit key from `getrandom`, its slot's pin map made to exist (once per slot, like the row maps) and
  emptied, the key written at `run_idx` with the run's gen, and last the header with `TEGO_SLOT_EXEC_PIN` and the
  launcher's pid namespace (`/proc/self/ns/pid`'s device in the kernel's encoding, and its inode). A run that cannot be
  pinned runs unpinned, its log saying why: pins never turn on in a state that would refuse every exec. The slot's
  clear (Detach, the reaper's purge, the next Prepare) zeroes its key and deletes its pins. `Handle.ExecPins` reports
  the key to the supervisor; `PinExec` writes a pin with the run's gen and its next seq, `SweepExecPins` deletes the
  pins of threads that are gone.
- **The supervisor** writes the pin of every exec it continues in a pinned run (`Options.ExecPinner`), after its
  decision and the `ID_VALID` that closes it, immediately before `CONTINUE`: the image's identity as the plane holds it
  (fdinfo's `ino` and the `s_dev` of its mount's super block from mountinfo, never `fstat`'s), its final name, the
  `bprm->filename` alloc_bprm spells (the path passed, or `/dev/fd/<n>[/<path>]` for an `execveat` relative to a
  descriptor), the form and `#!` chain a run with command rules read, and the argv elements the decision read (the
  whole vector under an exec gate). An exec whose pin cannot be built or written is refused (rule `exec.pin`,
  `pin_unavailable`); a full map is swept of dead threads' pins once first.

- **The flag.** `TEGO_SLOT_EXEC_PIN` (0x100) in the slot header, with the launcher's pid namespace (`pidns_dev` in
  the kernel's `major << 20 | minor` encoding, `pidns_ino`). Clear, bprm_check and the pin program return after one
  flag test.
- **Maps.** `tego_plane_exec_pins` (HASH_OF_MAPS by `run_idx`, inner HASH of 4096 `struct tego_exec_pin`, 160 bytes,
  `BPF_F_NO_PREALLOC`, keyed by `{tid in the launcher's pid namespace, start time in clock ticks}`),
  `tego_plane_pin_keys` (ARRAY of `{gen, k0, k1}` by `run_idx`) and `tego_plane_exec_armed` (TASK_STORAGE, 248
  bytes: the armed pin, its stage count, the vector's length the first stage counted, the outcome, the argv-guarded
  mark and the MAC's 64-byte chunk), which the
  recorder also declares, pinned by name, to read the pin seq into its exec record.
- **bprm_check**, first stage, before the `EXEC_DECIDES` return and the `#!` pass: clear the task's armed pin, look the
  pin up by its key, compare the gen, the image's `(s_dev, i_ino)`, a keyed MAC of its final name and one of
  `bprm->filename` (the whole spelling, then its NUL), refuse a guarded exec of a traced task, and move the pin into
  the task's storage, deleting the hash entry. A later stage must be the pinned chain's next interpreter (script
  form), is admitted only with `interp_ok` (unknown form; at the first later stage, after a binfmt_misc handler with
  the P flag, only when the decided argv[0] is the filename), or is refused (direct form). Every refusal is `-EACCES`
  with the plane's exec sample and a reason of `pin-missing`, `pin-mismatch`, `pin-unverifiable` or `exec-traced`; no
  path returns 0 because of a pin (`bpf/tests` `TestExecPinOnlyNarrows`).
- **`tp_btf/sched_process_exec`** (`tego_exec_pin_lsm`, `tego_exec_pin_fmr`, one per mode, attached with the hooks):
  MAC the mapped area (`[arg_start, arg_end)`, its covered prefix, its whole script vector, or its unknown-form tail:
  the filename and argv[1:], once the first stage's `bprm->argc` is the pin's)
  in 64-byte chunks read into the task's storage under `bpf_loop`, and on a difference, an unread area or no armed pin
  `bpf_send_signal(SIGKILL)` with a kill sample (`TEGO_EV_PLANE_EXEC_KILL`: seq, reason, `kill_err`, the mapped
  argv). Every sample's seq is the task's `cur_seq`, the value the recorder's exec record reads as its `pin_seq`,
  read before the check's first branch: a kill of a slot cleared since bprm_check, or of an exec no pin was armed
  for, names it too, 0 only when the task holds no state of the run (`bpf/tests` `TestExecPinKillNamesTheRecordsSeq`).
  The area check and the kill are global functions, verified once: the program verifies in 8,885 instructions on
  5.14, 6.8, 6.12 and 6.17 and 5,585 on 6.1 (2026-10-20; 11,800 on 7.0 before, not
  measured since), under the 20,000 budget.
- **ptrace.** `ptrace_access_check` (ATTACH) and `ptrace_traceme` refuse `process-scope` a peer of a task whose last
  exec passed a guarded pin, or of a thread whose group leader's did (the mark is the exec'ing task's, and the
  program's later threads share its mm).
- **Ring ABI.** `TEGO_EVENTS_VERSION` 4: `tego_ev_exec.pin_seq` appended, the kill sample's kind 30, and the held
  sample's kind 31 (`TEGO_EV_PLANE_EXEC_HELD`: seq, old tid, start), which the pin program reserves after a match and
  only there (`bpf/tests` `TestExecPinHeldOnlyAfterTheMatch`). The ledger's `argv_facts: kernel_pinned` rests on it, a
  positive sample, never on the absence of a kill; a ring with no room counts a lost sample, and the exec says
  `unproven`.
- **The line.** A pinned exec's one line is the kernel's: the supervisor writes the pin and hands its naming over
  (terminal ownership), and the recorder holds the exec record until the plane's held or kill sample of the same
  process and pin arrives (ADR 0048 (8); `observe` `TestExecPinFold*`): a sample pairs only with the record whose
  `pin_seq` is its seq, 0 included, and a half of another seq is an earlier exec's, settled alone, so under a ring
  loss no exec takes another exec's sample. A pinned exec whose kernel line is not live (no recorder
  reads the run) is refused by the supervisor, `exec.pin` with `pin_unavailable`, rather than continued with a line
  that could say `allow` over a kill. A kill the kernel could not send (`kill_err`) is followed by the launcher's
  SIGKILL through the process's pidfd, checked against the sample's start time.

## 3. The walk, the fill and the arming, as models

**The walk.** From the resolved dentry through `d_parent`, crossing to `mnt_parent`/`mnt_mountpoint` at a mount
root, at most 64 steps (a mount crossing is none: the mountpoint names the path the mount root did, and is not
looked up), one lookup per step in the slot's inner map. It is a global
subprogram verified once per program and called up to twice (rename and link walk both ends). Before 6.8
(`__arg_trusted`) the subprogram takes `u64` addresses and reads through `bpf_rdonly_cast` (6.2+) or CO-RE probe
reads, or becomes `__always_inline` per hook: TIER3-PLAN T0 decides by measuring load time on 5.14 and 6.1, and a
new ADR records it only if T0 forces the form.

**The fill.** `decide_fill.bpf.c`, an `iter/task_file` over the launcher's held O_PATH descriptors (ADR 0023),
task-scoped on 6.1+ (and RHEL 9.8's 5.14) and unscoped with a tgid filter below. Userspace never sees a key. Built at
T4 (§2.6).

**Arming.** The run's `tego_run_set` row is inserted after the child stage's first `execve` returned and before
the ack (ADR 0021 (2), ADR 0024 (10)).

## 4. Composition, modes, ledger and doctor

**Composition.** The effective rule is the plane's walk intersected with the Landlock domain the stage installs at
every tier. The filter keeps refusing `bpf(2)`, module loading and kexec (ADR 0033), relays connects, and notifies
for the record until step E. With a plane mode selected, no fanotify mark is placed.

**Modes.** `lsm` (`BPF_LSM_MAC`, needs `bpf` in the active LSM list), `fmod_ret` (`SEC("fmod_ret/security_<hook>")`,
any kernel where the hook set loads and CONFIG_LTO_CLANG is absent), `fanotify` (the fallback, ADR 0021). Two macros
emit both SEC forms from one body. Pins live under `/sys/fs/bpf/tego/<hash>-<mode>/`.

**Ledger (built for step A at T9, §2.8).** A refusal line carries `mechanism: plane`, `decision_plane:
lsm|fmod_ret` (a fanotify run writes no plane fields), the rule ID from `rule_idx` (ADR 0030) and a reason from the closed set (`read-denied`,
`exec-not-allowed`, the `*-outside-contract` codes, `path-unresolved`), with the plane's own cause where the set has
no code for it in `plane_reason`: `refer`, `deny-write-ancestor`, `identity-mismatch`. A refused mapping's rule is `exec-map` (step C); it is never a `plane_reason`.

**Doctor (built, §2.5).** D6 unchanged. D7's six `lsm/*` rows are one row per `decide.bpf.c` hook per mode with
BTF presence and prototype arity. A mode probe loads the mode's full set and checks each hook refuses in a scratch
cgroup (where its body decides) and passes outside it, with lockdown, LTO and `bpf_loop` checks; the result is
cached per boot and build (`runcache.go`) and adopted from the pin directory.

## 5. Business rules

**R1 — Scope is one cgroup lookup (built, T3).** Every plane program's first act is
`tego_run_set[bpf_get_current_cgroup_id()]`. A miss returns 0. No host process is decided; host processes pay the
lookup only (ADR 0024 (6)). A hit whose `gen` differs from the row it reads is R6's stale row, not a miss. Tests:
`TestPlaneHooksLookTheRunUpFirst`, and `TestPlaneStepAHooksDecide`'s cells outside the run.

**R2 — A decision is 0 or -EACCES and nothing else (built, T2 and T3).** The verifier leaves `BPF_MODIFY_RETURN`
unbounded, so this is a source-level rule of `decide.bpf.c`, checked by a unit test over the source and by the
verifier-load test on every hook. Refusals read EACCES in every tier; fanotify's EPERM exception and tier 3's
designed EPERM for exec end (ADR 0024 (7)). Tests: `TestPlaneReturnsOnlyZeroOrEACCES`, `TestPlaneLoadsAndAttaches`.

**R3 — The hook set and its steps (built for steps A to D, T3, T13, T14 and T15).** The plane attaches exactly
§2.1's hooks in landing order A, B, C, D, then §2.20's six. A hook is in the set only when it decides a contract
rule; `file_permission`, `task_kill`, and `socket_bind`, `socket_connect` and `socket_sendmsg` for inet families are not
(§1). *Amended 2026-10-05:* this said the LSM network hooks were not in the set; `socket_create`, step D's AF_UNIX
hooks and §2.20's `socket_bind` (AF_UNIX) and `socket_listen` are. A kernel lacking one hook (`file_truncate` below 6.2) drops that
hook alone, and the mode probe reports it; a hook the mode needs to keep a rule sound (R9, R10, R11) that fails the
probe fails the mode (R21). Built at T13 (§2.12): `bpf.PlaneHook.Optional` marks `file_truncate`, `inode_set_acl` and
`inode_remove_acl`; `bpf.PlaneHooksFor` leaves one out where the kernel's BTF lacks its target, in the backend's load
and doctor's probe alike, and doctor's row says which hook decides its rule there (`TestPlaneModeVerdict`,
`TestPlaneRowOK`, `TestPlaneAttachTargetsResolve`). Step D's `socket_connect` and `socket_sendmsg` are built at T15 (§2.11). Step C's `mmap_file` and
`file_mprotect` are built at T14 (§2.14); neither is optional.
§2.20's six are held in a governed run: `socket_bind` and `socket_listen` by `TestPlaneRunUnixListenerOutcomes` and
`TestPlaneRunIOUringListenerOutcomes`, and `ptrace_access_check`, `ptrace_traceme`, `key_permission` and `bpf` by
`TestPlaneRunControlPtraceIsRunScoped`, `TestPlaneRunControlKeyringIsTheContractsOptIn` and
`TestPlaneRunControlBPFIsRefused`, beside doctor's known answers.

**R4 — One body, two SEC forms (built for step A, T2 and T3; the `mmap_prot()` half at T14).** Each hook body is written once and exposed as `lsm/<hook>` and
`fmod_ret/security_<hook>`. In `fmod_ret` mode the body first reproduces what the `security_` wrapper does before
the chain: path hooks return 0 where IS_PRIVATE holds of the inode their wrapper tests (the directory for unlink,
rmdir, mknod, mkdir and symlink), and `mmap_file` computes the effective prot as `mmap_prot()`
does (READ_IMPLIES_EXEC on a mount that is not `noexec` adds PROT_EXEC) (ADR 0024 (8)). Every hook argument is read
with direct BTF loads; the walk's reads of kernel objects (`d_parent`, `d_inode`, the mount crossing's fields, the
ADR 0025 (4) identity fields, the name and unix-address words) go through the build's reader, `bpf_rdonly_cast` in
the rdonly build and CO-RE `bpf_probe_read_kernel` in the probe-read build (ADR 0024 (9)). Built: one body emits both forms and the
fmod_ret programs return 0 for an IS_PRIVATE inode, the wrapper's own (`TestPlaneHooksHaveBothSections`,
`TestPlanePrivateExitsTestTheWrappersInode`, `TestPlaneReturnsOnlyZeroOrEACCES`,
`TestPlaneLoadsAndAttaches`, `TestPlaneStepAHooksDecide`, §2.3, §2.7); the fmod_ret `mmap_file` program computes
`mmap_prot()` itself, since `security_mmap_file` is handed reqprot (`TestPlaneMapDecidesOnTheEffectiveProt`,
`TestPlaneStepCHooksDecide`'s READ_IMPLIES_EXEC cells, §2.14).

**R5 — The rows and the scratch (built: row values at T5, maps, keys and fill at T4 and T6).** The plane's maps are
§2.2's. Rows are keyed by the inode pointer the run's own Landlock domain pins (ADR 0025 (3)). Watch entries have no
row of their own that decides (ADR 0016 attributes them from the resolved path): a watch entry's path is a row carrying
the answer inherited from above, because the kernel's walk stops at every row. Userspace never reads or writes a key, with one exception: doctor's
known answers read one row of doctor's own unpinned scratch map back to corrupt its identity (§2.5), print no key, and
destroy the map with the probe; no run's map is ever read.
The values a row carries, `kind` and `rule_idx`, are §2.4's (`decide.CompilePlane`; `internal/bpf`
`TestPlaneCapsMatchRowCompiler` holds them to the C fields). Built at T6 (§2.9): each slot's maps made once and
kept, the rows keyed by the run's own Landlock-held descriptors (`TestPlaneRunEndToEnd`). A task whose scratch value
cannot be created (task storage out of memory) is refused path-unresolved, counted `unresolved` and sampled by the
record fallback (§2.17): the walk's pointers are laundered through that value, so no decision is made without it.

**R6 — Every row carries `gen`; a stale row is absent (the fill's half built at T4; the walk's at T2, its
decisions T3's; the clear's callers T6's, built).** A slot keeps its row maps like its rings:
the plan's amendment to ADR 0025, made because ADR 0026 measured each HASH_OF_MAPS insert or delete waiting an RCU
grace period (11.5 and 7.6 ms), and a per-run inner-map create and drop would add about 19 ms to kill test 4 go's
thin margin. A row whose `gen` differs from the run's counts as absent and the walk continues past it. That is
exact, because all the current run's rows exist before arming (R15). Slot reuse waits for "`gen` differs", not for
"inner map deleted" (ADR 0026 (6)); the slot's rows are cleared off the run's path, in Detach, `purgeSlot` and the
reaper. Built at T4 (§2.6): the fill writes every row with the run's gen, replaces a stale row at a repeated key,
deletes nothing on the run's path, and clears the stale rows in the kernel (`tego_plane_clear`, keeping this gen)
only when a map is too full of them to take the run's; `TestPlaneFillSlotReuseLeavesStaleRowsAbsent`. A stale
row walked past is not counted: it sits on the allow path of every action beneath it, where a counter shared by the
run's CPUs would bounce one cache line (`bpf/tests` `TestPlaneWalkStepCountsNothing`). Built at T6
(§2.9): Prepare, Detach and the reaper clear a slot; `TestPlaneStaleRowsOfTheSlotsLastRunAreAbsent`,
`TestPlaneLauncherKillLeavesTheRunDecidedAndTheReaperPurges`. The slot's header (`tego_plane_slots`, one per
`run_idx`: `{gen, flags, fs_rows, exec_rows}`) says which run the slot's rows are for and what its contract decides
beyond them: `exec:` (`TEGO_SLOT_EXEC_DECIDES`), `exec.anonymous`, unix names below 6.7, `net:` and an ICMP
destination. Prepare writes it last, after the fill and its check and before Arm; every clear zeroes it first; every
decided hook reads it after its run-set hit and its no-decision skips (an object no path names, a private clone: doctor's probe execs a memfd), before its first decision, and refuses, counting `norows`, when its gen is not the run's. A
missing row never reads as a permission: a section's absence is a flag left clear, never a policy row left out
(`TestPlaneEveryHookReadsTheSlotHeader`, `TestSlotHeaderSaysWhatTheRunDecides`, and as root `TestPlaneStepAHooksDecide`'s
cleared-header cells: an exec and a read under a nested `deny_read` refused with EACCES and counted, on a live
run-set row whose slot header was cleared). A run's gen is its slot's epoch (`slotTable.acquireGen`): one more than
the slot's last, never 0, kept in the slot table across release, repeating only after 2^31 - 1 runs of that one slot,
where the low half of a cgroup id repeated once kernfs's idr wrapped (ADR 0025's security argument). Detach clears
the slot only when every row naming it was removed: a run-set row it could not remove still carries the slot and its
tasks are decided by their own rows until the reaper takes both (`TestPlaneDetachKeepsACarriedSlotsRows`).

**R7 — The walk (built, T3).** As §3, with these outcomes and no others. The nearest entry wins (SEMANTICS §2):
the first current row, which is complete (§2.4). A disconnected root or an exhausted 64-step bound refuses with
`path-unresolved` and is counted (`unresolved`, `bound`). A step is a level climbed; a mount crossing costs none,
so the kernel's step is `decide.PlaneRows.Find`'s, path components only. The walk has `2 x (64 + 1)` iterations, a
lookup and a crossing at each level; a climb crossing more mounts than that (mounts stacked on one mountpoint) runs
out and refuses `path-unresolved` too. On every hit, `i_ino`,
`i_generation` and `s_dev` are compared with the row and `gen` with the run; a mismatch refuses and bumps a
counter. There are no strings and no `bpf_d_path` (unavailable to `path_*` below 6.8). Tests:
`TestPlaneWalkHasNoStringOps`, `TestPlaneWalkFailsClosed` (the enum order, the initial BOUND, the counts and
`tego_walk_failed`'s threshold, which no kernel cell reaches for a disconnected dentry), `TestPlaneStepAHooksDecide`
(a stale row absent, a corrupted identity refused and counted; a file 64 levels below a write row decided by it and
one 65 below refused and counted bound on open, rename, link and unlink; 64 components across a tmpfs still the
row's).

**R8 — `file_open` decides read and write, never exec (built, T3).** It refuses a read under `deny_read`, and
a write-open, `O_TRUNC` or `O_CREAT`-created file under a `deny_write` or a non-write entry per the contract. It
applies no exec row, so PT_INTERP's open of `ld.so` needs none. It returns 0 for a file on a private clone
(`tego_internal_mount`, MNT_NS_INTERNAL), FMODE_BACKING opens (6.6+) included: the user's own open of the overlay
file was decided (ADR 0024 (6)). The skip is keyed on the mount alone and reads no FMODE_BACKING bit, so no bit
misread from BTF can change its verdict (`TestPlaneOpenSkipKeysOnThePrivateClone`). An object no path names is no fs
decision (§2.7).
Tests: `TestPlaneFileOpenNeverAppliesExecRows`, `TestPlaneStepAHooksDecide`.

**R9 — `bprm_check_security` decides exec (built, T3).** By the file's inode, its parent directory's inode and
the final name's bytes, so a hard link under another name or in another directory is refused (SEMANTICS §4), and
each link an entry names is its own row (keyed by the link, §6 E15); by
`exec.anonymous` for an image with no path; and for a directly invoked loader unless listed. A `#!` stage passes and
the interpreter or native binary decides. Exec is decided only here. SEMANTICS §4's "allowed in tier 3 when its
interpreter is allowed" is withdrawn: tier 3 also installs Landlock, whose EXECUTE rule refuses an unlisted script
(ADR 0024 (4)); `compile --test`'s one plane column and `Evaluate` at `bpflsm` answer that composition
(`decide.ScriptFloor`, ADR 0019's 2026-09-30 note, `TestPlaneEvaluatorScriptMeetsTheLandlockFloor`). Tests:
`TestPlaneExecComparesTheWholeName`, `TestPlaneNameKey`, `TestPlaneStepAHooksDecide` (an image whose name was dropped,
unlinked after its open or an `O_TMPFILE`, is refused without `exec.anonymous` and runs with it, as a memfd does).

**R10 — REFER (built, T5 and T3).** `path_rename` and `path_link` refuse when the source's
nearest entry is stricter than the destination's, walking both ends. A `deny_read` file cannot be moved or linked out
of its tree. *Amended 2026-10-17:* the Landlock floor the run
keeps under the plane decides a link and a rename as well, with its own `REFER` (`MAKE_REG` and `REFER` on the ends'
directories, and no file right gained, an `exec.allow` directory's `EXECUTE` included), so `compile --test`'s
`bpflsm` column composes it after the plane's answer (`decide.LandlockLinkRefusal`, `decide.RenameGainedBy`), as it
composes the floor under a `#!` script; and the column asks `path_link`'s questions in the hook's order, both walks
before `MODIFY_ALLOW`, so a source whose walk cannot finish is `path-unresolved` wherever the new name lies
(`TestPlaneEvaluatorLinkMeetsTheLandlockFloor`, `TestPlaneEvaluatorLinkWalksTheSourceFirst`). *Amended 2026-10-17:* the floor's directory rights too: `path_rename`, `path_unlink` and `path_rmdir`
decide on the objects, and the floor asks `REFER` of a rename's two directories and `REMOVE_*` of an unlink's, which a
file-level write entry's own directory does not grant; the kernel refuses its rename and its unlink with `EACCES`, and
the `bpflsm` column and `Evaluate` at `bpflsm` compose both after the plane's answer (`landlockRename`,
`landlockDelete`), as they compose a link's (`TestBPFLSMKeepsTheLandlockFloorsDirectoryRights`, the conformance cells
`refer/rename-file-entry-across-directories` and `refer/unlink-file-entry` with their parity column). The rows-only
properties (`TestPlaneRowsMatchEvaluate`, `TestRootWalkMatchesEvaluate`) compose the same floor after the rows' walk.
The order is `decide.PlaneKind.Strictness` and the test `decide.PlaneReferRefused` (§2.4,
`TestPlaneKindStrictness`); the hooks are T3's (§2.7; `TestPlaneRenamesAndLinksKeepTheirRows`,
`TestPlaneStepAHooksDecide`).

**R11 — Ancestor rows for `deny_write` (built, T5 and T3).** A `deny_write` target's row refuses
every modification of it and beneath it (`path_unlink`, `path_rmdir`, `path_rename`, write-opens). Each directory from
it up to the outermost write entry enclosing it has a row with `PlaneRenameRefused`: `path_rename` of that directory
itself refuses (reason `deny-write-ancestor`; supervisor.md R15c in the kernel), while what the write entry allows
beneath it stays allowed. `mv .git .git.old` is refused; `touch .git/x` is not. An rmdir of such a directory needs no
bit: it is not empty while the target exists. Above the outermost write entry no write entry covers the directory, so
its rename is refused already. A target declared through a symlink (`.git/hooks` linked elsewhere, `Path` other than
`Resolved`) is protected at both spellings, as the model protects it: the link itself and each directory above it up to
the outermost write entry have rows too, keyed at their own inode (`PlaneRows.NoFollow`, held `O_PATH|O_NOFOLLOW` for
identity alone), so unlinking, renaming or replacing the link is refused at depth 0 on it. `decide.CompilePlane`,
`TestPlaneRowsDenyWriteAncestors`, `TestPlaneRowsKeyALinkedTargetAtItsOwnInode`, `TestPlaneNoFollowKeysHoldTheLinkItself`; the hooks are T3's (`TestPlaneRenamesAndLinksKeepTheirRows`,
`TestPlaneStepAHooksDecide`, whose symlink cells key a `.git/hooks` link at its own inode and refuse its unlink, its rename
(`deny-write-ancestor`, the link's own row) and a rename over it, with the target's files still refused), and `path_rmdir`
refuses under no entry and under `deny_read` (`delete-outside-contract`).

**R12 — Dentry-only hooks (step B) protect only (built, T13).** `path_chmod`, `path_chown` and the xattr and ACL
hooks walk `d_parent` inside the superblock and refuse only against a `deny_write` protection (Landlock governs none
of them). Prepare keys a row on every mounted root at or below a deny target, from mountinfo, so the walk meets it.
A mountinfo that cannot be read is `cgroup.ErrMountTable` for a table with a `deny_write` target, never a table
with no mount row: tier cgroup runs it on the fanotify listener and says why, tier bpflsm refuses it
(`ErrPlaneCannotHold`; `TestPlaneRowsRefuseAnUnreadableMountTable`).
A walk that reaches a superblock root with no row returns 0. On 6.2+, `setfacl` is refused through
`inode_set_acl`, which rewrites the mode without `path_chmod`. As built (§2.12): the rows carry `PlaneProtected`
where a `deny_write` target lies at or above them (`TestPlaneRowsProtectDenyWriteTargets`); the mounted-root rows are
`PlaneRows.WithMounts` over the launcher's mountinfo, for mountpoints strictly below a `deny_write` target, marked
`PlaneMountOnly` so the walk that crosses mounts passes them (`TestPlaneRowsWithMounts`,
`TestPlanPlaneFillMountRows`, `TestPlaneAttributeHooksProtectOnly`); a walk that fails refuses (R7); and
`TestPlaneStepBHooksDecide` refuses chmod, chown, setxattr, removexattr and setfacl on a `deny_write` target's file
and on a tmpfs mounted below it, and passes them in a write entry, outside every entry and under a `deny_read`.

**R13 — Create and truncate hooks (step B) leave no file (built, T13).** `path_mknod` runs in `may_o_create`,
before an `O_CREAT` create makes the inode, so a refused create leaves nothing. `path_mkdir`, `path_symlink`,
`path_truncate` and, where present, `file_truncate` follow the write entries. As built (§2.12): each is a
modification at its object by the walk that crosses mounts, as `path_unlink` is (`TestPlaneStepBCreatesAreModifications`);
`TestPlaneStepBHooksDecide` refuses an `O_CREAT` open, a mkdir, a mknod and a symlink under a row that refuses
modifications with no file left, and a truncate by path and by a descriptor opened before the run on a `deny_write`
target; `TestPlaneRunEndToEnd` refuses a mkdir and a create under a `deny_read` nested in a write entry in a real run,
with nothing left.

**R14 — Socket families and unix (steps B, D) (step D built, T15, §2.11; step B built, T13, §2.12).** `socket_create`
enforces ADR 0018's allowlist for every family and returns 0 when `kern != 0`. *Amended 2026-10-17 (ADR 0018 (7)):* it
cannot see a socket turned into another family after it is made: `setsockopt(SOL_TCP, TCP_ULP, "smc")` builds an
`AF_SMC` socket in place as a kernel socket, without `__sock_create`. `cgroup/setsockopt`, which every run with a
`net:` section attaches beside the plane, refuses `TCP_ULP` on every path, io_uring's `SOCKET_URING_OP_SETSOCKOPT`
included, so a plane run with `io_uring: true` keeps ADR 0018's bound (enforce-cgroup-observe R4). Where `connect_unix` is absent (below
6.7), `socket_connect` and `socket_sendmsg` decide a run's `unix:` entries, keyed by the socket's cgroup, by the rule
and rows `connect_unix` and `sendmsg_unix` use on 6.7+, and refuse every name of a run whose slot holds no unix
policy of its gen (`TestPlaneUnixHooksDecide`, `TestPlaneUnixVerdictOnRealKernel`,
`TestPlaneUnixHooksDecideAsConnectUnixDoes`, `TestPlaneFillCarriesTheUnixPolicy`). *Amended 2026-10-19 (supervisor R11c):* `socket_connect` also admits an abstract name no entry lists when the connect consumes the
one-connect grant of a person's approval, as `connect_unix` does (enforce-cgroup-observe R7): the row of
`tego_unix_approvals` for the run's slot and gen and the socket's cookie (read from the socket, `skc_cookie`), naming
exactly that name, live, taken once (`TestPlaneUnixApprovalOnRealKernel`). A declared `net.listen` is decided at
`socket_bind` and `socket_listen` (§2.20) and held in a governed run by `TestPlaneRunUnixListenerOutcomes` and
`TestPlaneRunIOUringListenerOutcomes`.
Step B as built (§2.12): only under a
`net:` section (the slot header's net flags, `TestNetPolicyRow`), the filter's allowlist (`TestPlaneSocketCreateIsTheAllowlist`),
through socket(2) and low-level io_uring fixtures (`TestPlaneStepBHooksDecide`). ADR 0113's C40
amendment now refuses `io_uring: true` in enforcing contracts that may select a root tier, because
rings bypass the local TCP control-port relay (`TestPlaneRunRefusesIOUring`). The lower-level
filter and backend fixtures retain coverage of their ring-handling code.

**R15 — Arming point (built, T6).** The `run_set` row is inserted after the stage's first `execve` and before
the ack. The tego binary's exec therefore meets no row and needs no admission, the agent cannot exist before the
row, and every row of R5 is already in place (ADR 0021 (2), ADR 0024 (10)). No kernel-side admission and no
`stage_pending` state exist. The row names the run's mode (§2.9); `TestPlaneRunPrepareArmDetach`,
`TestTier2ArmsAfterTheStageExec` (a deny_read over the tego binary, refused by the plane only after the stage's exec).

**R16 — The fill (built at T4; Prepare's call and the held descriptors' source at T6).** Rows are written by `decide_fill.bpf.c` over the launcher's held O_PATH
descriptors; a map carries the wanted descriptor numbers and row templates; the program keeps only the launcher's
tgid; for each descriptor it reports `(mnt_id, i_ino)`. Prepare compares these with the descriptor's `mnt_id` and
`ino` when it planned (statx; fdinfo's before 5.8) and fails on any mismatch, so a descriptor number reused on another
file fails Prepare. Where
task-scoped iteration is absent the unscoped cost is measured and stated. A cap on keyed inodes per
run is reported by `compile`. As built (§2.6): the plan records each descriptor's identity after checking it
names its path, and the kernel's report must equal it; a second row on one
fs inode, or on one exec link, fails, and each exec row is filled from a descriptor held at its own link (§6 E15); RHEL 9.8's 5.14 has the scoped link, and the unscoped pass (forced, on 6.17 and 5.14) costs 65-162 ms
against 200k foreign descriptors. `TestPlanPlaneFillRefuses`, `TestCheckPlaneFill`,
`TestPlaneFillWritesTheContractsRows`, `TestPlaneFillFailsOnAReusedDescriptor`, `TestPlaneFillUnscopedOnABusyHost`;
at T6 Prepare's last step from the Landlock plan's descriptors (§2.9), `TestPlaneFillFailureFailsPrepare`.

**R17 — Neutral Landlock rules pin the rows (rules computed at T5; the builder's application built at T6).** The
plan carries one neutral rule per keyed inode (ADR 0025 (3)), granting nothing: the plan's union at every path is
proven unchanged (`internal/policy/decide` `TestNeutralRulesKeepTheUnion`, over every generated table). The run's
domain therefore holds every keyed inode for as long as any member exists. A neutral rule carries READ_FILE and
READ_DIR only, where the domain already grants them (§2.4); a keyed inode with no read grant gets none, and Landlock
refuses every open there itself. The enforce/landlock builder applies `PlaneRows.Neutral` (§2.9,
`TestPlaneKeysAreHeldWithTheirNeutralRules`).

**R18 — Modes (built: doctor's probe, `bpf.plane` and the selection at T8, §2.5; the backend that loads a mode and
names its pin directory at T6, §2.9).** `lsm` where `bpf` is active and the set loads; `fmod_ret` otherwise where the
set loads and CONFIG_LTO_CLANG is absent; else the `fanotify` fallback. The mode is part of the pin directory name,
so two modes never share maps. `bpf.plane: auto|lsm|fmod_ret` is `/etc/tego/config.yaml` only and pins a mode for
operators and ADR 0017; `auto` prefers `lsm`. If a kernel drops the `security_` exemption, `fmod_ret` fails at load
and the probe falls to `lsm` or the fallback, never to silence. A test build's `TEGO_TEST_PLANE` pins the mode, or
`fanotify`, as `bpf.plane` would (`TestSelectPlane`, `TestPlaneRunEndToEnd`).

**R19 — Tier selection (built: doctor's derivation and `Report.PlaneFor` at T8, `TestBPFLSMNeedsLSMMode`,
`TestPlaneFor`; the tier's construction and refusal at T7, §2.10, `TestNewNeedsLSMMode`,
`TestTierBPFLSMNeedsLSMMode`, `TestLSMPlaneReachesTheTierThreeBackend`, `TestReportSelectsTierBPFLSM`,
`TestTierBPFLSMRunEndToEnd`; run_start's `decision_plane` on 2026-09-30, `TestRunStartNamesTheDecisionPlane`,
`TestPlaneRunEndToEnd`).** `bpflsm` needs `lsm` mode and is the plane in that mode. `cgroup` takes
the best of `lsm`, `fmod_ret`, `fanotify`. `auto` prefers `bpflsm`. A `--tier bpflsm` pin without `lsm` mode is
refused before Prepare, at selection, with doctor's GRUB fix (`lsm=...,bpf`), and never falls back silently; the
backend's Prepare refuses any other mode itself, and a table whose rows fail Prepare's second look after the slot
is held (a hard link made since the first) with `ErrPlaneCannotHold`, never tier cgroup's fallback to the listener
(`TestTierBPFLSMRefusesALateSharedInode`). At tier cgroup the same late failure is `cgroup.ErrPlaneRowsChanged`, and
the adapter composes tier 1 again without the rows and prepares again, so the run falls back to the listener with a
filter composed for it, never with the plane-only relaxations (io_uring admitted, the memfd arm dropped, R27) of the
filter composed from the rows (`TestLateSharedInodeRecomposesTierOne`,
`TestChoosePlaneRefusesHandedRowsThatNoLongerHold`). Tiers 2 and 3 enforce one
semantics; `run_start` records `decision_plane` (`lsm`, `fmod_ret`, or `fanotify` for tier cgroup on the listener;
absent for a tier with no plane; spec/record/v1, `record_minor` 2), so a run that refused nothing still says what
decided it, and the capability line reports `deny_read` nested in a write entry as enforced at tier 2 only once step
A is loaded (ADR 0024 (4)).

**R20 — Pins, adoption and lifetime (built, T6).** Programs are pinned under
`/sys/fs/bpf/tego/<hash>-<mode>/` and adopted by later runs; every map the plane's programs use is pinned by name,
since a later run adopts nothing otherwise (§2.18). Linger and sweep (ADR 0022) keep the up-to-2.3 s
cold attach and removal off the run's path; a build is never removed while a row exists. Launcher death changes
nothing the plane decides (ADR 0020). A pinned program or link is adopted only when its program reads this
plane's maps and the build's current ones; one pinned over maps since re-created is unpinned and replaced, and a
build whose plane directory cannot be removed keeps its own pins, so no run set is re-created under a plane.
`TestSweepTakesABuildsPlanesWithIt`, `TestPlaneLauncherKillLeavesTheRunDecidedAndTheReaperPurges`,
`TestPlaneStaleLinkOverARecreatedBuildIsNotAdopted`, `TestPinsRemoveKeepsTheBuildUnderAPlaneItCannotRemove`,
`TestPlaneRunAdoptsThePinnedPlane`, `TestAdoptedObjectsPinEveryMapByName`.

**R21 — A mode is selected only when every hook counted (built in doctor at T8, §2.5; the pin directory's writer
at T6, §2.9).** doctor's mode probe loads the mode's full set. In a scratch cgroup it performs one syscall per hook
that must be refused (where the hook's body decides; a stub's must pass), and outside it a matching action that
must pass. It checks BTF presence and the prototype of every `security_` and `bpf_lsm_` function used, `bpf_loop`
(none: no mode), lockdown (`confidentiality` without `bpf_rdonly_cast` in BTF: no mode, because probe reads are
refused under it on every kernel, ADR 0024's T0 note) and CONFIG_LTO_CLANG (no `fmod_ret`). Then it decides known
answers on this kernel (§2.5): a scratch slot filled through the real fill from doctor's own fixtures, and one
action per cell (a `deny_read` row two levels up across a tmpfs mount, a stale-gen row, a corrupted identity, a
path 64 and 65 levels below a row, a directory exec row, a file exec row and a hard link of it under another name,
an rmdir), each of which must give its exact verdict and fail-closed counters. The result is cached
per boot and build in `runcache.go` and adopted from the pin directory, so an adopting run probes nothing. A mode
failing any hook or any known answer is never selected (`TestPlaneRowOK`, `TestSelectPlane`,
`TestPlaneModeVerdictNeedsEveryKnownAnswer`, `TestIntegrationPlaneProbeOnThisKernel`,
`TestIntegrationPlaneProbeRejectsAFlippedKnownAnswer`, `TestAdoptingRunProbesNoPlane`).

**R22 — Composition (built through T16, §2.13, §2.15 and §2.19).** The Landlock domain and the seccomp filter are installed at every tier
and are not weakened by the plane (I3). With a plane mode selected: no fanotify marks; the supervisor's best-effort
exec, `deny_write` and loader refusals (GAPS C30 a and b, C31, supervisor.md R15c) are decided by the kernel
instead; enforce-cgroup-observe E15, E16, E17, E24, E34, E35, E37, E39 and E40 are fallback-only (the static
non-PIE requirement this list named is gone from the fallback too since ADR 0021 (4); the shipped builds keep that
linking for portability, docs/VERSIONING.md §5). Built (§2.9): no group and no mark in plane mode, `TestPlaneRunEndToEnd`; the supervisor's
half is §2.9's condition 1. Built at T16 (§2.13): the fs half, as R27's narrowed filter, since the supervisor
refuses nothing it is not notified of; it is enabled with the path-naming recorder built in §2.15 and gated per
loaded hook. Exec handover is built at §2.19: metadata notifications remain, and complete live kernel outcome recording removes supervisor exec decisions. Missing coverage retains those decisions and their records.

**R23 — The recorder and one verdict line (built for step A at T9, §2.8).** ADR 0016's fexit programs on `file_open`,
`path_mknod`, `path_mkdir`, `path_rmdir`, `path_unlink`, `path_rename`, `path_link`, `path_symlink`, `path_truncate`
and `file_truncate` read the chain's return and the plane's `rule_idx` from task storage. On every other hook
(`bprm_check`, chmod, chown, xattr, ACL, `mmap_file`, `file_mprotect`, `socket_create`, the unix hooks) the plane
emits its own refusal sample, and never on a hook with a recorder fexit. There is at most one verdict line per
action. Built: the five step A hooks with a recorder fexit take the decision by hook and object, and `bprm_check`
writes its sample; step B adds theirs, and step C's two write `TEGO_EV_PLANE_MAP` (§2.14); step D's unix hooks write none as built: the supervisor's line is the
action's, as on 6.7+ (§2.11's condition 1). Built for step B at T13 (§2.12): the fexit programs on `path_mknod`,
`path_mkdir`, `path_symlink`, `path_truncate` and `file_truncate` take the decision (`TestRecorderTakesThePlaneDecision`),
and the attribute hooks and `socket_create` write the plane's own sample (`TestPlaneStepBRefusalsWriteTheirSample`,
`TestRecorderNamesPlaneAttrAndSocketRefusals`). Built at T9b (§2.17) for the ten hooks a fexit wraps: where the
build's fexit on one is not attached (`tego_plane_recorded`), its refusals write the plane's own sample
(`TEGO_EV_PLANE_FS`) instead, so the line is the fexit's or the plane's, never neither and never both
(`TestPlaneFallbackOnEveryFexitHookRefusal`, `TestRecorderNamesPlaneFallbackSamples`, the root
`TestIntegrationPlaneFallbackIsOneLine`).

**R24 — Ledger lines (built for step A at T9, §2.8).** As §4: `mechanism: plane`, `decision_plane`, `rule` from
`rule_idx`, `reason` from the closed set, and `plane_reason` for a cause the set has no code for. A refusal carries the run's `gen`; the plane's samples go to the run's own ring
(ADR 0026). The slot's fail-closed counters (`tego_plane_counts`: mismatch, unresolved, bound, norows) are read at
run end and each non-zero one is one `gap what=enforce` line with its count and `decision_plane` (§2.8's counters;
built 2026-09-30, `TestPlaneCountersBecomeGaps`, `TestPlaneCountersAreTheSlotsNamedCounts`,
`TestTheReaperRecordsThePlaneCounters`, `TestPlaneCountersBecomeGapsAtRunEnd`).

**R25 — Verdict parity (the model's half built at T5, the column at T10, the kernel cells at T11).** The row compiler (ADR 0028
S4) and `compile --test`'s `bpflsm` column both come from `internal/policy/decide`'s root model, so `Evaluate` at
`bpflsm` equals the rows by construction (`TestPlaneRowsMatchEvaluate`, with §2.4's two stated conditions), and
ADR 0017's conformance cells check both against the kernel. Tier `cgroup` (plane) and `bpflsm` share one column;
they split into mode columns only when a conformance cell differs (ADR 0019's condition). The fanotify column goes
with ADR 0028 S3. `CAPABILITIES.md` and `pkg/spec/backend/matrix.go` land as one golden pair (built at T10: the tier 3 cells and the `decision plane` row, `TestMatrixGolden`; `TestCompileTestBPFLSMColumnGolden`, `TestCompileTestBPFLSMColumnJSON`, `TestPlaneEvaluatorMatchesEvaluate`, `TestPlaneEvaluatorExecMatchesEvaluate`).

Built at T10: `compile --test`'s `bpflsm` column is `decide.PlaneEvaluator`, the rows walked as the kernel walks them (fs by `PlaneRows.Decide`, exec by `ExecMatch` then the read of each file the exec opens, rename by both ends then REFER; *amended 2026-10-17:* a link and a rename then meet the Landlock floor's REFER, and with fs notifications held a link at a `deny_write` end is the supervisor's R15c refusal, named by the target), so it is what the loaded programs decide and not a second model; `Evaluate` at `bpflsm` is the oracle the rows are property-tested against. Its `--json` cells and the header say `decision_plane: lsm`. Every conformance cell now carries a bpflsm/lsm expectation that the compile runner checks. Built at T11: the kernel runner checks the cells against the kernel on the tier bpflsm axis and on tier cgroup's plane-mode axes, and on the bpflsm axis checks the kernel against this column directly, cell by cell, as runner `parity` (`TestConformanceKernel`, `test/conformance/kernel_integration_test.go`), baselined like the other runners.

**R26 — mmap and mprotect policy, step C (built, T14, §2.14; the compile warning and `compile --test`'s `exec.map` built after it).** With an `exec:` section, the plane refuses (rule
`exec-map`, reason `exec-not-allowed`): a PROT_EXEC mapping of an anonymous file unless `exec.anonymous`; one of a
file whose nearest fs entry is a write or ask entry and that no `exec.allow` covers; a PROT_EXEC and PROT_WRITE
private file mapping; an `mprotect` adding PROT_EXEC to a file mapping with `anon_vma` set. Both bodies return 0
before the `run_set` lookup when the file is NULL or PROT_EXEC is absent. For FMODE_BACKING the walk starts at
`backing_file_user_path()` on 6.8+. ADR 0027 is accepted before this step lands. `compile` warns for ELF shared
objects or native-module trees under write entries no `exec.allow` covers (`exec-map`, agent-contract E39,
`TestNativeCodeUnderWriteEntryWarns`; §2.14's condition 2). "Covers"
is `bprm_check`'s three arms: an exec.allow directory above the file, its own exec row, a name row. Tests:
`TestPlaneMapHooksReturnBeforeTheRunLookup`, `TestPlaneMapDecidesOnTheEffectiveProt`, `TestPlaneMapPolicy`,
`TestPlaneStepCHooksDecide`, `TestPlaneExecMapRunEndToEnd`.

**R27 — Step C drops the memfd arm; step E stops the notifications (the notifications' mechanism built at T16 per loaded hook, §2.13, its fs half enabled, §2.15; the memfd arm built at T14, §2.14).** Once step C is loaded and
probed, the seccomp arm refusing every `memfd_create` where MFD_NOEXEC_SEAL is missing is dropped at tiers 2 and 3
(the MFD_NOEXEC_SEAL arm stays; tier 1 is unchanged). With steps A and B loaded, ADR 0026 in place and ADR 0016's
producer table live, the filter stops notifying write-opens and fs mutations unless the contract has `fs.ask`
entries (P1) (ADR 0024 (13), (14)). Built per hook (§2.13): a notification stops only when every hook that decides
each form of the syscall is loaded and attached for the run's mode, so a kernel or a build without a hook keeps its
notification; nothing stops with an `fs.ask` entry, without a plane, or without a recorder that names path hooks by
path (observe's, since §2.15), and under `record: full` the open family stays notified (`TestPlaneFilterDropsOnlyWhatLoadedHooksDecide`,
`TestPlaneFilterIsTheLoadedHooksAndOnlyOnceUsed`, `TestPlaneFilterIsUsedOnlyWithARecorder`). *Measured 2026-10-06 (kill test 5,
§10.1):* what an `fs.ask` entry costs a run at tiers cgroup and bpflsm is the notifications it keeps: on kill test 4's pip build
19 become 2,509, which is 160 to 692 ms a run (60 to 280 µs each), and on the 20-step agent nothing. Built for the memfd arm
(§2.14): a run carries plane rows only in a mode the probe selected with step C's hooks refusing
(`landlock.Run.PlaneMaps`); `TestMemfdArmDroppedWhereThePlaneMaps`, `TestInheritedRunDropsTheMemfdArmOnlyWithAPlane`,
`TestPlaneExecMapRunEndToEnd`.

**R28 — Kernel matrix (T11 harness built; arm64 runs in CI's hosted runner from 2026-10-06, its result not yet recorded).** The plane is verified on every MATRIX row per TIER3-PLAN §7 (table below),
and its rows are ADR 0017 cells:

| Row | bpf LSM | bpflsm | tier cgroup mode |
|---|---|---|---|
| RHEL 9 5.14 | yes | yes | lsm |
| AL2023 6.1 (no `file_truncate`) | yes | yes | lsm |
| Ubuntu 24.04 6.8, Ubuntu 25.10 and the development machine 6.17 | no | after a GRUB drop-in | fmod_ret (lsm on the boot with `bpf` added: Ubuntu 25.10's two boots, measured 2026-10-05) |
| Debian 13, RHEL 10 6.12, Fedora 7.0 and 7.2 | yes | yes | lsm (Fedora 7.2 measured 2026-10-05) |
| Ubuntu 22.04 5.15 (Landlock ABI 1) | no | no tier is offered | none: doctor offers no tier cgroup, so no plane is selected (a doctor-only matrix row) |
| lockdown=confidentiality without `bpf_rdonly_cast` in BTF (AL2023 6.1) | – | no | fanotify |
| no `bpf_loop` in BTF (below 5.17, no backport) | – | no | fanotify |
| arm64 (the hosted runner; no guest row) | not measured | probe decides | fanotify expected until measured |

*Amended 2026-10-06:* the arm64 row has no KVM guest (a TCG guest was set aside: too slow for the suites,
and it adds no kernel the runner lacks), so GitHub's arm64 runner is its row. `ci.yml`'s `build-test-arm64` runs
there, as root, what needs no new code: `TestPlaneLoadsAndAttaches` and `TestPlaneStepAHooksDecide` (the plane's hook
sets load, attach and decide), `TestIntegrationAsRoot` and `tego doctor --require cgroup` (doctor's answer for the
kernel), `TestPlaneRunEndToEnd` and `TestPlaneRunNamesTrueUnderRenamesAndMountMoves` (a run decided by the plane, and
the recorder's walk against renames and mount moves), the freeze, arming and process-start tests of ADR 0021, and
`TestPlaneSeqcountStress` (§2.15). Each plane test must pass in `fmod_ret` mode, so a runner whose probe selects no
plane fails the job, with doctor's report beside it: that, or a mode and its numbers, is what fills this row. Nothing
has run there yet. The log of the first run is what this row
is changed from, with the kernel and the `SEQCOUNT-STRESS` lines it prints. ADR 0017's conformance on arm64 is the
step the conformance work adds to the same job.

## 6. Edge cases

1. **A run beside a run (built, T6; `TestPlaneConcurrentRunsOfOneBuildAreIsolated`).** Two concurrent runs of one build each see only their own rows: the outer
   map is keyed by `run_idx`. A hook in run B never reads run A's inner map.
2. **A reused slot (built in the walk, T3; `TestPlaneStepAHooksDecide`'s next-run cells).** A new run in a slot whose previous rows are not yet cleared meets rows with
   the old `gen` and treats them as absent (R6). A slot whose purge was interrupted is not reused while any row or
   ring carries it.
3. **A recycled inode pointer (built, T3; `TestPlaneStepAHooksDecide`'s corrupted row).** The freed inode's pointer reused by another inode matches a row by
   key but fails the `i_ino`, `i_generation` or `s_dev` compare and refuses with a counter bump. It cannot happen
   for a keyed inode while the domain holds it (R17).
4. **btrfs subvolumes and overlayfs (overlayfs built, T3 and T13; btrfs acceptance built 2026-10-04).** Subvolumes repeat inode numbers
   under one superblock, which is why the key is the pointer and the check is fdinfo's `mnt_id` and `ino`, never
   userspace `st_dev` as the kernel superblock device. `TestPlaneRunBtrfsSubvolumeInodeIdentity` verifies the actual fill, rows, compile/model and allowed/refused reads on one mounted filesystem (*amended 2026-10-05:* in every root run of the tegobpf suite; until then a skip-allowed manual fixture, §2.19). Overlay opens are decided on the user's open; the backing open is skipped (R8), and so are copy-up's
   plain opens on overlayfs' private clones of its layers (§2.12; `TestPlaneStepAHooksDecide`'s overlay cells,
   `TestPlaneFileOpenSkipsPrivateClones`).
5. **A bind mount over a deny target (the mounted-root rows built, T13).** The walk crosses `mnt_parent` at each mount
   root, so a bind of a `deny_read` tree elsewhere in the run meets the row. A tmpfs mounted below a deny target has
   its own mounted-root row (R12; `TestPlaneStepBHooksDecide`'s tmpfs cells).
6. **An unmount after launcher and reaper both die (a residual by design; nothing to build).** The domain's hold ends with the last member;
   an unmount that frees an inode while a member exists is the stated residual of ADR 0025 (5).
7. **An SCM_RIGHTS descriptor from outside the run (a residual by design: no `file_permission`).** Not re-decided: there is no `file_permission`.
   Stated residual (§9).
8. **A symlink swapped during a decision (built, T13).** The decision is on the dentry the hook holds locked;
   the swap cannot change it. Step B's symlink-swap cell tests this: a thread repoints a symlink between a write
   entry's file and a `deny_write` target's through 3,000 chmods and 3,000 truncates, and the target never changes
   (`TestPlaneStepBHooksDecide`).
9. **An ancestor renamed during the unlocked `d_parent` walk (the refusing rows built, T3; the rename-race cell is T13's).** Cannot loosen a rule: REFER and
   ancestor rows refuse loosening moves (§7's argument). The walk may refuse spuriously, never admit.
10. **Kernel-internal opens (built, T3; `TestPlaneStepAHooksDecide`, `TestPlaneFileOpenNeverAppliesExecRows`).** Opens the kernel makes for a stacking filesystem are not re-decided
    on a path no rule names (R8). A `#!` stage's own bprm passes (R9).
11. **Launcher SIGSTOP or SIGKILL mid-run (SIGKILL built, T6; SIGSTOP has no cell; `TestPlaneLauncherKillLeavesTheRunDecidedAndTheReaperPurges`).** Changes nothing: pins, domain-held inodes and the reaper
    (ADR 0020). An open under a `deny_read` beneath a write entry stays refused with caches dropped.
12. **A pinned tier the machine cannot run (built, T7; `TestReportSelectsTierBPFLSM`, `TestTierBPFLSMRunEndToEnd`).**
    `--tier bpflsm` where `bpf` is not active is refused before Prepare with doctor's fix (R19); it never becomes
    tier `cgroup` silently.
13. **The keyed-inode cap (compile's report built at T5; Prepare's refusal at T7, `TestTierBPFLSMRefusesATableThePlaneCannotHold`).** A contract naming more
    inodes than the cap is reported by `compile` and refuses Prepare, never truncated. The cap is the slot maps' sizes,
    4096 fs rows and 1024 exec rows, the mount rows among the fs rows, the bare-name rows among the exec rows; over it, `tego compile` fails when the table compiled to bpflsm and warns when an
    auto run may land there (§2.4; `decide.PlaneDiagnostic`, `TestPlaneCap`, `TestPlaneDiagnostic`).
14. **A hook missing on this kernel (built, T13).** `file_truncate` on 6.1, `inode_set_acl` below 6.2: the mode
    is selected without the hook where the rule it decides is otherwise covered, and the capability line names the
    gap (R3). As built, doctor's plane row names the hook that decides the rule there (`TestPlaneModeVerdict`); the
    capability line names no gap, since none is left.
15. **A multi-call binary: hard links of one inode under several names (built 2026-09-30; ADR 0025's note of that
    day).** uutils coreutils on Ubuntu 25.10 (114 links of one file, reached through `/usr/bin` symlinks) and busybox
    install one executable under many names. Each name `exec.allow` lists runs under its own entry, and every other
    name, in the same directory or another, is refused: an exec row is keyed by the link (the inode, its directory's
    inode and its name's key, `tego_exec_link_key`), a hit matches only when the row's inode, directory and name
    bytes are the exec'd dentry's, and the fill keys each row from a descriptor held at that link (the Landlock plan
    holds one per listed link beyond an inode's first, identity only). A symlink chain is decided at the link it ends
    at, the entry's resolved path. Fail closed: a dentry with no parent inode matches no row; a link whose name is not
    the entry's, or whose path was replaced while held, fails Prepare. Which command the binary runs is its own choice
    from `argv[0]`, outside every exec rule (§9). `TestPlaneFillKeysEachHardLinkOfOneInode`,
    `TestPlaneFillRefusesOneLinkTwice`, `TestPlaneStepAHooksDecide`'s second-link cell,
    `TestPlaneExecLinksHoldEachLinkItsEntryNames`, `TestPlaneExecRowsAreKeyedByTheLink`, `TestPlaneRunMulticallLinks`
    (tier cgroup in both modes and tier bpflsm, the ledger naming each link), ADR 0017's `exec-multicall-*` cells.

## 7. Failure modes and handling

- A row map missing under a live `run_set` row refuses (fail closed) and bumps the counter.
- A mode that fails to load or fails any hook of its probe is not used; the run gets another mode, the fallback with
  its capability line, or a refused Prepare for a pinned tier (R19, R21).
- The fill disagreeing with the planned identity fails Prepare before arming; nothing runs.
- A walk that cannot resolve refuses `path-unresolved` and counts.
- A fexit recorder that cannot attach leaves the plane's own sample in its place (R23), never two lines (built at
  T9b, §2.17: the build's `tego_plane_recorded` mask, written by the backend from the links it holds, sends every
  refusal on a hook whose fexit is not attached to the plane's own `TEGO_EV_PLANE_FS` sample; a mask nobody wrote
  samples every refusal; `TestIntegrationPlaneFallbackIsOneLine`).

**Security argument.** (a) Fail-closed: the plane only refuses; admitting too much falls to the Landlock floor,
refusing too much fails closed. (b) TOCTOU: decisions are on `bprm->file`, the opened file and the path hook's
locked dentry, so there is no check-to-use gap; the remaining race, an ancestor renamed during the walk, cannot
loosen a rule because REFER and ancestor rows refuse loosening moves. (c) Launcher death changes nothing. (d) Scope
and visibility: cgroup-scoped, named and pinned in tego's bpffs directory, listed by doctor, removed by gc; the
agent cannot reach `bpf(2)` (ADR 0033).

## 8. Invariants

1. **A host process is never decided (built, T3).** A program with no `run_set` hit returns 0 at its first
   instruction after the lookup (R1). Kill test cells and the host-open cells hold this.
2. **A program returns 0 or -EACCES (built, T3).** No other value on any path (R2).
3. **The plane never widens the floor (built for step A: `TestNeutralRulesKeepTheUnion`, T5, T6; the kernel-side cell is T11's).** The Landlock domain and seccomp filter are installed
   unchanged; the effective rule is the walk intersected with them; the neutral rules grant nothing (R17, R22).
4. **A decision is on the object the kernel resolved (built for step A, T3).** No path string, no userspace-supplied key,
   no `bpf_d_path` (R5, R7).
5. **A row outlives no slot it does not belong to (built, T6).** A slot is reusable only when no `run_set` row,
   no current-`gen` row and no inner ring carries it (R6); ADR 0026's I5 is extended to say so. `TestPlaneStaleRowsOfTheSlotsLastRunAreAbsent`.
6. **One mode's maps are never another's (built, T6): and one mode's programs decide only its own runs (§2.9).** The pin directory name carries the mode (R18). `TestPlaneHooksDecideOnlyTheirModesRuns`.
7. **No silent fallback (built for tier cgroup, T6, and tier bpflsm, T7).** A mode or tier that cannot run is reported by doctor, the capability
   line or a refused Prepare, never by a quieter run (R19, R21); `run_start`'s `decision_plane` names what decided
   every run of tier cgroup or bpflsm. `TestPlaneRunEndToEnd`, `TestPlaneFor`, `TestRunStartNamesTheDecisionPlane`.
8. **At most one verdict line per action (built for step A at T9, for steps A and B with the recorder detached at T9b).** Recorder fexit or plane sample, not both and not neither (R23, §2.17).
9. **compile --test at `bpflsm` equals the ledger's verdict (the column built at T10; the kernel cells at T11, `TestConformanceKernel`'s runner `parity`).** Both come from the root model (R25);
   ADR 0017 checks the kernel against it.
10. **The plane adds no userspace decision to the TCB (built, T4: the fill writes keys in the kernel and the check reads only `(mnt_id, ino)`; `TestPlaneFillWritesTheContractsRows`, `TestCheckPlaneFill`).** Row keys never cross to userspace; the
    core that computes rows is pure (ADR 0028).

## 9. Residuals

- In `fmod_ret` mode a refusal skips the other LSMs' hooks for that access, their audit included.
- An unmount after launcher and reaper both die (ADR 0025 (5)).
- A descriptor received by SCM_RIGHTS from outside the run is not re-decided.
- A mount made after the fill by a process outside the run: the walk follows the mount tree as it stands,
  so a directory outside every write entry bound beneath one is written, and an overlay whose lower layer is
  a `deny_read` directory is read through its merged path. A bind of a keyed deny target itself stays refused.
  `TestPlaneRunWalksTheMountTreeAsItStands` demonstrates these outside-root changes. Since NET09 (ADR 0055),
  the mandatory `capable` hook refuses CAP_SYS_ADMIN in every user namespace for plane-governed tasks, launched
  or adopted: mount APIs and mount-namespace creation/installation are refused, including new mount APIs and
  descriptors prepared before adoption. Other uses of that capability are also refused. A user namespace alone
  may still be created but cannot change the mount view. Doctor's invalid-descriptor move_mount probe must
  return EBADF outside the scope and EPERM inside, with the hook's run count increasing; missing BTF, load,
  attachment or functional proof makes the mode unavailable. Already-completed pre-attach changes, an operation
  already past its capability check at the arm, and mounts changed outside the run remain residuals.
- Root outside the run can read inode addresses (heap, not text) from the maps and can detach the plane.
- Anonymous executable memory (GAPS A2); code mapped from a readable pre-existing file outside write entries and
  never modified (ADR 0027).
- A multi-call binary chooses its command from `argv[0]`: busybox runs any applet through any listed name (uutils as
  Ubuntu builds it refuses a mismatched `argv[0]`). No exec rule sees `argv[0]` (§6 E15, SEMANTICS §4).
- A `deny_write` target's timestamps and inode flags are not protected: no hook is on `inode_setattr` or
  `file_ioctl`, and Landlock has none of them, so an agent that owns the target (or, for `utimensat` with NULL times,
  may write it by DAC) can set its atime and mtime, and `FS_IOC_SETFLAGS`/`FS_IOC_FSSETXATTR` can set flags that need
  no `CAP_LINUX_IMMUTABLE` (`noatime`, `nodump`). Its contents, name, mode, owner, xattrs and ACLs stay protected
  (R12); mtime-based checks (make, rsync) over it are not. Tiers 1 and 2 refuse neither (agent-contract E35).
- arm64 is unmeasured; the probe decides and the fallback is expected. CI's `build-test-arm64` runs the plane's own
  tests there as root from 2026-10-06 (R28), and its first log is what measures it. *Amended 2026-11-02:* that
  runner's 7.0 kernel is built `SMP PREEMPT`, so fmod_ret mode is ruled out there (ADR 0024 (16)) and the job checks
  doctor's refusal instead of a plane run; under the test builds' `TEGO_TEST_PLANE_PREEMPT=waive` it still requires
  `TestPlaneSeqcountStress`'s fmod_ret cell (§2.15's walk on a CPU that reorders loads), which under the waiver
  measures the walk and counts its wrong allows without holding them; the plane's programs still load, attach and
  decide there as `internal/bpf`'s tests load them.
- A kernel program skipped by the trampoline's per-CPU recursion check (ADR 0024 (16)). fmod_ret mode is admitted only
  where doctor proves the kernel never preempts kernel code, read afresh at every run and adoption, and LSM programs
  take no such check. Not covered by this (docs/GAPS.md C53): root changing a dynamic kernel's mode while a run lives
  is not watched; recursion misses are not detected at run time; `cgroup_track`'s `cgroup_mkdir` and the recorder's
  tracing programs are skipped the same way in every mode on a kernel that preempts kernel code, a recorder skip
  dropping its record with no `tego_lost` count (enforce-cgroup-observe §7).
- Host cost while a build is attached: a lookup per host open, exec, mmap and path operation (ADR 0024 measured
  +0.2 µs per open; LSM mode +25 to +72 ns more than `fmod_ret`).

## 10. Tests

Written: T2's source and layout tests (§2.3, the return discipline and `TestPlaneLoadsAndAttaches`' instruction budget
among them), T5's row compiler tests (§2.4), T8's doctor tests (§2.5), T4's fill tests (§2.6), T3's hook tests (§2.7,
the root `TestPlaneStepAHooksDecide` among them), T9's record tests (§2.8), T6's end-to-end and slot tests (§2.9) and
T10's column tests (R25), T9b's fallback tests (§2.17); both guest boots pass. Built at T11 and after (TIER3-PLAN §10's T11 row records what is not green): the verifier-load tests (`-tags tegobpf`,
root, KVM guest) on every MATRIX row, not only the 6.17 guest, RHEL 9.8 and AL2023; KVM root
suites (each hook refuses in the run and allows outside it and in a second run; REFER; `mv .git .git.old`; direct
`ld.so`, PT_INTERP and memfd exec; hard link; SIGKILL with `drop_caches`; btrfs and overlayfs; lockdown boots);
ADR 0017 conformance with a mode axis; kill tests 1, 4 and 7 at `bpflsm`, kill test 4 go within 2x bare (19 of 20)
with open cost at most 2 µs in the 20,000-open loop; kill test 5 (what an untouched `fs.ask` and `net.ask` entry costs,
`test/e2e/kt5-ask.sh`, §10.1) at every tier; `tier2-pairs.sh` with no stall (the script is built; ADR 0021's pairs runs, its forced-fallback shape, are an open condition). Tickets T2 to T16 of
TIER3-PLAN §10 build the rules above; the ticket that builds a rule marks it built and names its test.
*Added 2026-10-06:* `TestPlaneSeqcountStress` (§2.15) is the stress cell for the directory walk's
ordering and for the plane's refusals under renames, in each plane mode, held by `test/vm/root-must-pass.txt`; its
oracle and agent are unit-tested without root (`TestStressChain*`, `TestStressTally*`, `TestStressAgent*`). The
plane's load, step A, doctor, run end-to-end, freeze and arming tests run on arm64 in `ci.yml`'s `build-test-arm64`
(R28).

### 10.1 Performance budgets and the guest perf suite

`make vm-perf` (`test/vm/perf.sh`, `PERF_BOOT=bpf|default`, and `PERF_KERNEL=<matrix row>` for a row's own kernel in place of this host's; another row's figures are informational, since the budgets are the 6.17 guest's) builds a `tegobpf,tegotesthooks` tego, `test/perf/cmd/openbench`
(a raw open+close loop, one pinned CPU) and `test/perf/cmd/perfsuite`, boots one KVM guest and runs seven checks: **cold** start per
mode after `tego gc --builds`; **start**, the warm start per mode with a per-phase breakdown (`internal/platform/startphase`:
`probe`, `probe.<D-check>`, `select`, `compile`, `enforce.prepare`, `prepare.lock-slot|rules|load|fanotify|inherit|fill|filter`,
`prepare.rearm` and `prepare.rearm.start` (inside `prepare.lock-slot`: the pass over the other builds' timers, ADR 0022, and
one timer's start in it),
`load.obj.*`, `load.plane`, `plane.*`, `compose`, `attach` (the run's cgroup links and their pins, from 2026-10-17),
`stage`, `arm`, printed as `tego-phase <name> <us>` on stderr when a test build
has `TEGO_TEST_PHASE_TIMING` set); **fill**, Prepare's fill at 1, 1000 and the largest table the plane takes under the cap
(cap-8 on the 6.17 guest: the table also holds the write directory's and mounts' rows); **open**, 200,000 opens on one pinned CPU
per mode, the modes alternated in 9 rounds and read as each mode's best round, at `record: off` and `summary`; **socket**
(added 2026-10-16, ADR 0018 PR 2), 200,000 socket(AF_INET, SOCK_STREAM, 0)+close at landlock and on tier `cgroup`'s fanotify
fallback, alternated in 9 rounds, whose difference is `cgroup/sock_create`'s cost on an admitted socket
(`socket.excess.cgroup_ns`, limit 2000 ns, target 300 ns; 66 ns on 6.17, enforce-cgroup-observe §9), and from
2026-10-17 (ADR 0018 (7)) 200,000 setsockopt(TCP_NODELAY) on one socket in the same runs, whose difference is
`cgroup/setsockopt`'s cost on an option it passes (`setsockopt.excess.cgroup_ns`, limit 2000 ns, target 300 ns; 155 to
259 ns on 6.17 on a loaded host); **conc**, 2, 8
and 32 gated concurrent runs per mode with tier landlock as the control, and the fanotify fallback at 2 and 8. A limit in
`test/perf/perf.go` fails the run (exit 1); a figure over its **target** (the number a spec or ADR states) and inside its limit
prints `TARGET-MISS` and is an open condition below, never a relaxed limit. `-budget name=value` moves a limit (a limit set under a
measurement fails the run: checked, exit 1). Start and cold are judged on the best of their runs, because the guest shares a host
with other tenants that only ever add time. `go test ./internal/runtime/enforce/cgroup -run PlanPlaneFill -bench PlanPlaneFill` is
the host-side benchmark of the plan half of the fill at 1, 1000 and cap-1 rows (30 us a row), with a 200 ms budget at 1000
(`TestPlanPlaneFillStaysUnderItsBudgetAt1000Rows`, asserted in budget mode since 2026-10-16: Changes).

**Cold attribution** (added 2026-10-19). A test build launched with `TEGO_TEST_LOAD_STATS` beside
`TEGO_TEST_PHASE_TIMING` attributes each BPF collection load it makes (`internal/bpf` `loadstats_*`): the verifier is
asked for its statistics (`BPF_LOG_STATS`, log level 4: the closing "verification time" and "processed N insns" lines,
no per-instruction log), the load is split at each program's `load_time` (`bpf_prog_info`, set before `bpf_check`) into
`load.obj.<obj>.maps` (map creation and the loader's preparation of the first program) and one
`load.prog.<obj>.<prog>.{wall,verify}` span a program (`plane.obj.<mode>.maps` and `plane.prog.<mode>.<prog>.*` for the
plane, `probe.plane.prog.<mode>.<prog>.*` for the plane probe's), with `tego-stat <name>.{insns,states,peak}` counts,
and a sampler reads the loading thread's kernel stack every 50 ms and prints the commonest frames of any span over 500
ms as `tego-phase-stack <name> <samples> <frames>`. D7 times each hook as
`probe.hook.<hook>.{load,verify,attach,detach}`, the plane probe each mode as
`probe.plane.<mode>.{load,attach,exercise,known,detach,total}`, and `probe.programs` holds `probe.d7` and `probe.plane`.
A product build has none of it: `LoadOptions` is cilium/ebpf's zero options and no trace starts
(`TestProductLoadOptionsHaveNoLog`); a test build without the knob loads as the product does. The parser is held to each
kernel's own count by `TestLoadStatsMatchKernel` (`verified_insns`, 5.16 and later). `perfsuite` takes the budgeted cold
samples as it did before the attribution existed, with no `TEGO_TEST_LOAD_STATS` (the measurement method is
unchanged, so `cold.<mode>.ms` and `cold.bootfirst.ms` never carry the attribution's cost), and under
`-cold-attribution` (on by default) follows each with an attributed sample of the same mode after its own `gc --builds`.
Every sample prints a `cold-attribution` record (`load_stats` says which kind it is; its phases, D7's hooks' and the
plane probe's modes' steps among them, which every timed launch prints; the per-object, per-hook and per-mode sums; an
attributed sample's counts and stacks; the launcher's peak RSS and the CPU pressure the sample ran under), and a mode's
attributed samples a `cold-attributed` record (their best and median, and `cost_ms`, their best less the budgeted best
of the same guest). The boot's first run is a budget sample, so its record has D7's per-hook load, attach and detach but
no verifier statistics. The `cold` record keeps the budgeted samples' coarse phases' medians; `-cold-attribution=false`
takes the budgeted samples alone. `-cold-settle` adds, a mode, as many samples again that wait after `gc --builds` until
no function that had a BPF trampoline before it is still in ftrace's `enabled_functions`, less what the kernel traced
before the boot's first run (6.8's HID-BPF holds `__hid_bpf_tail_call`; so `-cold-settle` needs `cold` as the first
check) (`cold-settled`, with that wait and the trampolines' count; a trampoline that outlives 60 s ends the mode's
settled samples and is named in a `cold-settle-timeout` record): a diagnostic, never a budget, and `cold.<mode>.ms`
stays the budgeted immediate samples' best (a settled sample is attributed under `-cold-attribution` and is read against
the `cold-attributed` best, like for like). (Waiting for the removed builds' link IDs to go, the first form, settles
nothing: `bpf_link_free` frees a link's ID before it releases the link, so the IDs were gone within 0.4 ms of gc's
return while the next load still waited seconds on a trampoline.)

**Cold attribution, measured 2026-10-19** (the tree of that day plus this attribution; `make vm-perf
PERF_ARGS='-checks cold -cold-settle'`; 6.17.0-41 guest, 4 vCPUs, 3 GiB, three guests a boot and a fourth at the bpf
boot; one guest a matrix row, `lsm=…,bpf` boot; the host shared with other jobs, load average 1.4 to
13 during the runs, so every figure is the best of its samples and the CPU pressure is in each record). Raw records: one
`cold-attribution` line a sample in the console logs. The suite as it stood that day launched every cold sample
attributed, the budgeted ones included, so the first two rows carry the attribution's cost (below; the budgeted samples
launch unattributed since, Changes). Kernel 6.17, best of the four bpf-boot guests and of the three `default`-boot ones:

| Measure (6.17) | cgroup lsm | cgroup fmod_ret | bpflsm | `default` boot, fmod_ret |
|---|---|---|---|---|
| boot's first run (budget `cold.bootfirst.ms`, target 2.3 s) | 17.8 s | | | 13.6 s |
| cold, best of 3 after `gc --builds` and 1 s (`cold.<mode>.ms`) | 6.8 s | 5.6 s | 5.5 s | 6.0 s |
| cold after the teardown has finished (`cold-settled`) | 4.0 s | 3.7 s | 4.0 s | 4.0 s |
| teardown after gc returns (its traced functions untraced) | 4.2 s (37) | 3.0 s (27) | 4.1 s (37) | 3.0 s (27) |
| a cold load's wait in `bpf_trampoline_get` (stack samples) | 2.7 to 3.3 s | 1.4 to 3.1 s | 1.7 to 3.2 s | 1.4 to 2.0 s |
| `trace_proc` verification, settled (`load.prog.trace_proc.*.verify`) | 3.1 s | 3.0 s | 3.1 s | 3.2 s |
| the plane's load, settled (`load.plane`; its verification) | 0.55 s (0.40) | 0.39 s (0.23) | 0.56 s (0.42) | 0.44 s (0.27) |
| `cgroup_net`, `cgroup_track`, every object's maps | 62, 32, 20 to 25 ms | | | |

- **`trace_proc` is verification.** The build every kernel with `bpf_rdonly_cast` loads (`tracerd`, ADR 0024's
  lockdown note) processes 3,026,514 instructions in 19 programs on 6.17 and 5.14 (4,651,734 on 6.8); the nine path
  hooks (`tego_path_{link,mkdir,mknod,rename,rmdir,symlink,truncate,unlink}`, `tego_file_truncate`) are 333,410 to
  340,802 each, about 375 ms each on 6.17, and the other ten 101 to 4,103. The probe-read build `trace`, which AL2023's
  6.1 loads (no `bpf_rdonly_cast`), processes 106,692 and verifies in 24 to 52 ms, and its cold start meets the target
  there (0.61 to 0.95 s). The rest of an object's load (its maps, CO-RE, the JIT) is 30 to 45 ms.
- **The cold start inherits the previous build's teardown.** `gc --builds` returns while the kernel still releases the
  removed build's trampolines on 27 (fmod_ret plane) or 37 (LSM plane) functions (`bpf_link_put` defers to a
  workqueue; each release holds the trampoline's mutex through `ftrace_shutdown`'s RCU-tasks waits). The next load's
  `check_attach_btf_id` waits in `bpf_trampoline_get` for 1.4 to 3.3 s of it (the stack samples of every cold sample),
  and a sample taken after the trampolines are gone has no such wait and is 1.5 to 2.8 s faster (best against best;
  1.2 to 4.1 s within one guest). On 7.0 and 7.2 the same teardown takes 70 to 107 ms and no load waits.
- **The boot's first run is D7 and the plane probe verifying and detaching.** `probe.programs` is 13.8 to 15.5 s (bpf
  boot) and 9.8 to 10.7 s (`default`): D7 6.0 to 7.5 s, of which loading its 27 hooks is 4.2 to 5.3 s (verification
  3.4 to 4.7 s: the same 3.08 million instructions Prepare verifies again for `trace_proc` a moment later) and closing
  their links 1.8 to 2.2 s (attach 23 to 30 ms); the plane probe 3.5 to 4.0 s a mode, of which closing the mode's links
  is 3.1 to 3.3 s (load 0.3 to 0.6 s, attach 40 to 100 ms, exercise and known answers 0.02 to 0.3 s).

Matrix rows (informational; one guest each, best of three samples; a row over a 6.17 limit exits 1 there,
which is a figure, not a gate):

| Row | boot's first | cold lsm / fmod_ret / bpflsm | settled | teardown after gc | `trace_proc` verify (insns) | D7 detach; plane-probe detach |
|---|---|---|---|---|---|---|
| rhel-9 5.14 | 30.1 s | 11.6 / 8.5 / 10.6 s | 7.7 / 6.2 / 7.9 s | 3.4 to 4.8 s | 2.6 to 2.8 s (3.03 M) | 1.5 s; 6.5 s (attach 1.8 s; 6.6 s) |
| al2023 6.1 | 14.8 s | 0.95 / 0.89 / 0.61 s | 0.85 / 1.07 / 0.66 s | 0.1 ms | 24 to 52 ms (0.11 M) | 2.7 s; 10.3 s |
| ubuntu-24.04 6.8 (two guests) | 31.2 s | 14.0 / 8.1 / 8.5 s | 9.8 / 9.1 / 10.0 s | 3.2 to 4.4 s | 3.7 to 6.2 s (4.65 M) | 1.5 s; 6.6 s (attach 1.8 s; 6.6 s) |
| debian-13 6.12 | 23.6 s | 7.5 / 6.9 / 7.4 s | 3.6 / 3.8 / 3.2 s | 3.9 to 5.3 s | 2.4 to 3.0 s (3.03 M) | 2.8 s; 7.6 s |
| al2023-6.12 | 25.6 s | 11.3 / 11.7 / 9.6 s (load 8) | 7.8 / 4.0 / 4.7 s | 5.3 to 7.5 s | 3.1 to 6.0 s (3.03 M) | 4.1 s; 11.2 s |
| fedora-7.0 | 10.5 s | 3.4 / 3.4 / 3.4 s | 3.4 / 3.4 / 3.4 s | 71 to 107 ms | 2.8 s (3.03 M) | 0.23 s; 0.16 s |
| fedora-7.2 | 10.4 s | 4.2 / 4.3 / 4.3 s | 4.3 / 4.2 / 4.4 s | 82 to 94 ms | 3.4 to 3.6 s (3.03 M) | 0.21 s; 0.11 s |

On 5.14 and 6.8 attaching is slow too: the plane's load at a run is 2.2 to 3.7 s, of which verification is 0.2 to
0.4 s, and D7's and the plane probe's attaches take 1.8 s and 6.6 s.

**Decision gates, read from these numbers:**
- **G-H2, teardown overlap: met.** Immediate minus settled is 1.5 to 2.8 s on 6.17 (over the gate's 1 s) and the
  stacks show the `bpf_trampoline_get` waits; so on 5.14, 6.12 and AL2023's 6.12. Build removal must finish the kernel
  teardown before it returns. It is not the harness's: the linger sweep and
  `tego stop` unpin the same way.
- **G-H1, pure verification: met.** `trace_proc`'s verification is 3.0 to 3.9 s on 6.17 with no wait in it (over the
  gate's 1.2 s), nine path hooks of about 335 thousand instructions each; the verifier-size work is required, and the probe-read build's 107 thousand say how much of it the reader choice alone costs.
- **G-detach, the probes' link closes: met.** D7's and the plane probe's detaches are 8.1 to 8.4 s at the bpf boot's
  first run and 4.9 to 5.1 s at the `default` boot's (over the gate's 1 s); closing them off the run's path is required.

Every figure above is still a printed `TARGET-MISS` (and, on this loaded host, a 6.17 cold figure crossed its 9 s limit
in four of 14 guests, two of them without the attribution, with load averages up to 13); no limit or target moved. What
the attribution itself costs is not resolved on this host, and it is not zero: in four interleaved pairs of guests on
6.17's bpf boot (the suite of that day, `-cold-attribution=false` against its default), the per-pair differences have
both signs (-1.6 to +1.5 s cold, -4.6 to +4.9 s at the boot's first run, a pair at load average 12.7 left out), but best
of four is higher with it in every mode: 6.8 / 5.8 / 5.7 s cold (lsm / fmod_ret / bpflsm) and 18.2 s first without it
against 7.9 / 6.3 / 6.3 s and 18.8 s with it (+0.5 to +1.1 s cold, +0.6 s first), while the boot's first `trace_proc`
load, which no teardown precedes, is at best 3.16 s attributed (ten guests) and 3.54 s not (four). So the budgeted
samples no longer carry it: since the fix of 2026-10-19 (Changes) they launch unattributed, as before the attribution
existed, and each guest's `cold-attributed` records print the attribution's cost best against best beside them. The
first guest of the fixed suite (6.17, bpf boot, `-checks cold -cold-settle`, host load average 2.2 to 3.6) took the
boot's first run and the budgeted cold samples unattributed (17.9 s; 8.2 / 5.7 / 6.5 s) and printed the attribution's
cost as -0.37 / +0.16 / +0.24 s: one guest's best of three does not resolve it either. (Rejected: keeping the budgeted
samples attributed and saying so, which leaves an unresolved cost in the figure later work is measured against; and
turning the attribution off by default, which leaves the campaign's budget figures attributed.)

**The teardown overlap, fixed and measured 2026-10-19.** A build's removal now
returns only once the kernel has released the build's links (enforce-cgroup-observe R14's amendment: each link opened
before its pin is removed and closed after, then a wait, at most 30 s, until the kernel has freed the programs they
ran). Two 6.17 bpf-boot guests back to back on the same host, `-checks cold -cold-settle`, best of three, the tip
before the change first:

| Measure (6.17, bpf boot) | before | after |
|---|---|---|
| cold, `cold.<mode>.ms` (lsm / fmod_ret / bpflsm) | 7.52 / 6.42 / 7.03 s | 5.11 / 4.52 / 4.45 s |
| teardown left after `gc --builds` returned (`cold-settled` wait) | 4.2 to 4.4 / 3.1 to 3.3 / 4.3 to 4.6 s | 0.2 ms in every sample |
| cold after that teardown has finished (`cold-settled`) | 4.84 / 4.51 / 4.38 s | 5.43 / 4.69 / 4.59 s |
| `trace_proc`'s load in the budgeted cold samples, best | 6.58 / 5.69 / 6.11 s | 4.13 / 3.77 / 3.57 s |
| the boot's first run (`cold.bootfirst.ms`) | 18.8 s | 20.4 s |

The cold start is now the settled one (within the samples' spread), and `trace_proc`'s cold load is its verification:
in every attributed sample after the change its wall time exceeds the sum of its programs' verification by 7 to 12 ms,
and no stack sample shows a wait in `bpf_trampoline_get`. That verification ran at 3.5 to 4.5 s in these guests (3.0
to 3.2 s in the table above, on a quieter host), so `trace_proc`'s cold load fell back to its verification and toward
the boot-first ~3 s, not below it; the rest of the gap to the 2.3 s target is later work. A `default`-boot
guest after the change, on a busier host (verification 4.8 to 6.4 s), measured cold `fmod_ret` 6.66 s, settled 6.08 s,
the same 0.2 ms left after `gc --builds` and the same 10 ms between `trace_proc`'s wall time and its verification. The
teardown's own cost moved into the removal: `TestBuildRemovalReleasesLinksBeforeReturn` and
`TestPlaneRemovalReleasesLinksBeforeReturn` time it at 0.1 to 6.1 s for a build and 3.1 to 4.8 s with a plane on 6.17
and RHEL 9's 5.14, which the linger timer pays off any run's path. Every cold figure is still a `TARGET-MISS`; no
limit or target moved.

Findings that changed code: the plane's objects were **never adopted** by a later run of a build (`tego_plane_path_buf`, added
unpinned, made `adoptObjectIn` refuse the object, so every run loaded and verified it again, 420 to 980 ms, and left the copy
unattached; `bpf.KernelOnlyMaps` and `TestEveryUnpinnedMapIsKernelOnly` now hold it), and each of the 13 optional-hook BTF lookups
copied and indexed the whole kernel BTF (130 to 220 ms; the copy is shared once per process, `bpf.KernelBTF`). Warm start at tier
`bpflsm` fell from 1.1 to 1.5 s to the figures below.

Results, 2026-09-30, kernel 6.17.0-41 in a 4-vCPU, 3 GiB guest on a shared host (figures move with the host's load: the same build
measured 152 ms at bpflsm on a busy host and 90 ms on a quiet one; the table is the quiet run):

| Measure | landlock | cgroup lsm | cgroup fmod_ret | bpflsm | Limit / target |
|---|---|---|---|---|---|
| warm start, best of 8 (`lsm=bpf` boot) | 16 ms | 85 ms | 90 ms | 90 ms | limit 250 / 1000 ms; bpflsm minus landlock 74 ms, target 130 ms |
| warm start, `default` boot (no bpf in `lsm=`) | 19 ms | n/a | 136 ms | n/a | same |
| cold start, best of 3 after `gc --builds` (`lsm=bpf`) | n/a | 3.3 s | 1.8 s | 2.1 s | limit 9 s, target 2.3 s |
| cold start, `default` boot | n/a | n/a | 2.0 s | n/a | same |
| the boot's first plane run | | | | 8.8 s (`bpf`), 5.9 s (`default`) | limit 30 s, target 2.3 s |
| fill, 1000 rows | | | | 27 ms (Prepare 45 ms) | limit 1000 ms |
| fill, 4088 rows | | | | 127 ms (Prepare 158 ms; contract compile 56, Landlock compose 139) | limit 2000 ms |
| fill, `default` boot (cgroup, fmod_ret plane), 1000 / 4088 rows | | | 49 ms / 208 ms | | same limits |
| open+close over landlock, worst of three paths (`summary`) | 0 (1.9 us) | +938 ns | +833 ns | +791 ns | limit 2000 ns (kill test 4) |
| open+close over landlock (`off`) | | +281 ns | +224 ns | +264 ns | |
| 32 concurrent runs, open ratio to landlock's | 1 | 1.07 | 0.79 | 0.84 | limit 1.5 |
| 32 concurrent runs, all running | 0.3 s | 2.1 s | 1.1 s | 1.0 s | limit 10 s |

The fanotify fallback does not scale: an open costs 85 us with 2 runs (x28 the landlock control) and 1.3 ms with 8 (x227);
doctor's plane clause says so where the fallback is selected. The warm start's remaining excess at bpflsm is `probe.btf` (D2's
parse and CO-RE check, 33 ms here, 110 to 190 ms on a loaded host) and `load.plane` (20 ms).

Open conditions (none is relaxed in the suite):
1. **Kill test 4's 130 ms start allowance** is met on a quiet host (74 ms over landlock) and missed on a busy one (about 300 ms).
   Levers, largest first: keep D2's answer in the run cache (R27 says D2 is probed afresh on every run; it is the largest phase left),
   and `trace_proc`'s adoption. Proposed budget: warm start at bpflsm at most 1 s and at most 600 ms over tier landlock (the suite's
   limits), target 130 ms.
2. **Cold start** was 1.8 to 3.3 s after the build is removed (ADR 0022 says up to 2.3 s), and 5.9 to 17 s for the first
   plane run of a boot, on 2026-09-30. On 2026-10-19 it is 5.5 to 6.8 s and 13.6 to 17.8 s on the same guest (attributed
   samples), and "Cold attribution" above says where it goes: `trace_proc`'s verification, the removed build's teardown,
   and doctor's probes; all three decision gates are met, so the listed steps (removal that finishes the teardown, the
   probes' detach off the run's path and the verifier size) are required. Cold limit 9 s, target 2.3 s, linger
   unchanged at 5 minutes (ADR 0022). The removal step is built (2026-10-19, "The teardown overlap, fixed" above): the cold start
   is 4.5 to 5.1 s on 6.17's bpf boot, the settled figure, and `trace_proc`'s cold load is its verification; the probes' detach and
   the verifier size remain.
3. **fmod_ret against lsm**: the raw loop finds the two within 130 ns of each other in either direction (`fmod_ret` minus `lsm`:
   -105 to +128 ns at `summary`), so ADR 0024's ordering (25 to 72 ns) is below this rig's resolution and not reproduced, and the
   python probe's +2 us for fmod_ret did not reproduce either. ADR 0024's cost line is amended.
4. The one-statx-per-descriptor change is in (§2.6, R16). The fill here is 0.03 ms a
   row; the 0.5 ms a row seen earlier is the fill (0.03), the contract compile (0.014) and the Landlock compose (0.034) together with
   a busy host's probe.
5. The guest's hard `RLIMIT_NOFILE` is 4096 and a table of n rows holds about n descriptors in tier 1's compose (enforce-landlock E11),
   so the suite raises it; a launcher under a hard limit below the table's rows is refused at Prepare, as E11 says.
6. **An `fs.ask` entry keeps every fs notification (R27, ADR 0024 (14)); kill test 5 measures what that costs.**
   `test/e2e/kt5-ask.sh` (`make vm-matrix`, `VM_ONLY=kt5`; results in `test/vm/README.md`) runs kill test 2's 20-step agent and
   kill test 4's pip build under one contract with an `fs.ask` and a `net.ask` entry the workload never touches and the same
   contract without them, ten pairs each, and passes a cell when the median is slower by less than 1% of wall time or 1 s,
   whichever is larger. On 2026-10-06, on the 6.17 guest's two boots and on `debian-13`, `rhel-9`, `ubuntu-24.04`, `al2023`,
   `al2023-6.12` and `fedora-7.0`, every cell passed, at tiers cgroup (LSM and `fmod_ret`) and bpflsm: the pip build's
   notifications go from 19 to 2,509 and it runs 160 to 692 ms slower (8 to 26% of the run; 60 to 280 µs for each of the 2,490
   kept, `held_ms` up by 100 to 335), over 1% of wall time and inside the allowance by its 1 s, and the 20-step agent, whose
   run notifies twice, is within 12 ms. At tier landlock, and on the fanotify listener, the entries change nothing (the filter
   there notifies every write-open and mutation either way). The condition is the margin: the allowance closes near ten
   thousand kept notifications a run, so a larger build than the pip workload would miss it at these tiers, as
   TARGET-MISS, not as a moved budget. The follow-up is a narrower gate, an ask-only filter arm that keeps only the
   write-opens whose path can match an ask scope; it is not built, since the budget holds for the workloads R7 names.
7. **ADR 0043's name entries (C10), first measured 2026-10-20** (6.17 bpf boot, `test/vm/perf.sh -checks
   start,open,name`). Every plane run now carries the built-in `.env` entries,
   so `start` and `open` above ran with the header's name flag set: kill test 4 holds (`open.excess` cgroup-lsm 986,
   fmod_ret 916, bpflsm 981 ns, limit 2000), warm starts cgroup-lsm 71.8, fmod_ret 63.5, bpflsm 68.8 ms (bpflsm 40.7 ms
   over landlock, target 130). The name check (perfsuite `name`) alternates the suite's contract ("set") with the same
   contract and `deny_read: []` ("clear": no built-in list, flag clear), nine rounds in each plane mode, and reads
   medians: `fill.name.ms` 0.14 ms (limit 5: 64 name rows and 8 scope rows over none) and the warm start set over clear
   (-9.9, -3.1, -6.3 ms; report, target 5) hold. The per-open figures do not resolve: set over clear for a name with no
   lead (`open.name.miss`, target 30, limit 100) is +204, +170 and -376 ns (cgroup-lsm, fmod_ret, bpflsm), for `.envrc`
   (`lead`, limit 300) +516, +462, +75, for a directory rename (`rename.dir`, limit 2000) -228, +115, -509; and a
   refusal by name over one by the file's own row in the same run (`refused`, limit 1000) is 456, 1028, 1058 ns at three
   levels and 154, 238, 4 ns at 32 (`refused.deep`, report, target 1000). Signs that flip between modes, and a deep
   refusal cheaper than a shallow one, put these figures inside the run-to-run noise (two runs of different contracts
   several hundred ns apart either way), so the suite printed OVER for miss and lead in the two cgroup modes and for
   `refused` in fmod_ret and bpflsm, and neither a miss nor a pass is shown. The check therefore runs only when asked
   (`-checks name`), its limits unchanged; resolving them needs a design that pairs the flag within one run (open
   condition, ADR 0043 Implementation notes).

## 11. Open questions

- The walk's form on kernels before 6.8. Answered at T0 and T2: a global subprogram over `u64` addresses laundered through task storage, `bpf_loop(64, step)` (§2.3, ADR 0024 (1)).
- Whether the unscoped fill on 5.14 is affordable on a busy host. Answered at T4 (§2.6): RHEL 9.8's 5.14 has the
  scoped link; forced unscoped, 200k foreign descriptors cost 65 ms (6.17) to 162 ms (5.14) a fill.
- Whether one plane column suffices in `compile --test` (split only when a conformance cell differs, R25). Answered
  2026-09-30 for the unlisted script: the column composes the Landlock floor (R9), so no split; the nested-deny_read
  mkdir cell was step B's (T13).

**Changes.**
- 2026-10-20, R10 (ADR 0029 (4)): the Landlock floor's rename rule the `bpflsm`
  column composes is named as the code asks it, `decide.RenameGainedBy`; `decide.RenameGains`, a wrapper over it
  that only decide's tests called, moved into decide's test files. No column changed.
- 2026-10-20 (ADR 0048 P2): §2.22's kill sample names the task's `cur_seq`, as the exec
  record's `pin_seq` does, on every kill path, and the fold pairs a sample only with the record of its own seq (no
  kill of seq 0 pairs with any waiting record). Under a ring loss of an exec's held sample, a later exec's kill of a
  cleared slot or an unarmed pin, named seq 0, took the earlier exec's record and logged that exec, which ran, as
  refused.
- 2026-10-27: §10.1 condition 7 records the name entries' first guest figures: kill
  test 4, the warm start and `fill.name.ms` hold with the header's name flag set; the per-open name figures are inside
  the run-to-run noise, so the suite's `name` check runs only when asked, its limits unchanged.
- 2026-10-27 (ADR 0043 C11): §2.20's name entries are on in every build: `CompilePlane` emits a table's
  scope and name rows and compacts covered per-file rows (D6), Prepare writes the header's flag and fills the name map
  for every table with name entries, and doctor's known answers always include the seven name cells (§2.5). The build
  switch `agent.NameEntriesEnforced` and the test hook `TEGO_TEST_NAME_ENTRIES` are gone.
- 2026-10-27 (ADR 0043 C9): §2.5's known answers gain the name cells in a build that enforces name
  entries; `ProbeRows` carries the name map's outer and each known slot's inner map and fills the name entries through
  the run's own writer (`writeNameEntries`), and a mode that answers a name cell wrongly is not selected
  (`TestIntegrationPlaneProbeAnswersTheNameCells`, `TestIntegrationPlaneProbeRejectsAFlippedNameAnswer`).
- 2026-10-19: §10.1 "The teardown overlap, fixed and measured": a build's removal
  returns once the kernel has released its links (enforce-cgroup-observe R14), so a cold start no longer waits for the
  previous build's trampolines; open condition 2 says the removal step is built. No budget moved.
- 2026-10-19 (ADR 0048 P2): §2.22's ptrace hooks read the argv-guarded mark of the target's
  thread group leader as well as the target's. A thread a guarded program started after its exec had no mark, so a
  peer of the run could attach to it or write its memory, the argv area included.
- 2026-10-19 (ADR 0048 P2): §2.22's check of an interpreted unknown-form exec (an exec gate
  alone) holds the vector's length the first stage counted to the pin's, and its tail covers the filename in front
  of argv[1:]; a first binfmt_misc handler with the P flag is refused unless the decided argv[0] is the filename. A
  racing thread could put arguments in front of the decided argv[1:] and the exec still said `kernel_pinned`.
- 2026-10-19 (ADR 0048 P2): §2.22's fold pairs an exec record only with the sample of its own
  pin (the same seq, or a kill that names none); a waiting half of another seq is settled alone. An earlier exec's
  held sample could make a later killed exec's line say the mechanisms' verdict, beside the kill's own refused line.
- 2026-10-19 (ADR 0048 P2 K6, K7): §10's race cells fail on a record-loss gap (`ringbuf-full`, `channel-full`,
  `exec-fragment-overflow`) before comparing counts; the symlink swap, interpreter swap and kill-failed cells are in
  the tree (the last with the recorder-side hook `TEGO_TEST_EXEC_PIN_KILL_ERR`), and a sent pidfd backstop kill is
  logged as a failed one is. The perf suite gains its `exec` check (ADR 0048 K7's budgets, `test/perf/perf.go`); its
  figures are not yet recorded.
- 2026-10-19 (ADR 0048 P2 K5): §2.5 adds the exec pin cell (`plane.exec_pin`): a pinned scratch slot through
  `ProbeRows.FillPinned` and `PutPin`, the pin program in the probe's collection, and the answer pin's version 2 with
  its flags byte.
- 2026-10-19 (ADR 0048 P2 K4): §2.22 adds the held sample (kind 31), the fold that makes a pinned exec's one line, and
  the activation: a run with command rules or an exec gate that can escalate asks for pins, and Prepare grants them only
  with the recorder's exec outcomes.
- 2026-10-19 (ADR 0048 P2 K1, K2, K3): §2.22 describes exec pins: the plane's pin steps and program (K1), Prepare's key,
  pin map and header, and the supervisor's pin writes (K2, K3). No run asks to be pinned until K4's fold.
- 2026-10-19: §10.1 "Cold attribution": a test build with `TEGO_TEST_LOAD_STATS`
  attributes each cold load per program, map, D7 hook and plane-probe mode, and `perfsuite` prints it per cold sample
  (`-cold-attribution`, `-cold-settle`). Product builds load with unchanged options; no budget moved. "Cold
  attribution, measured 2026-10-19" replaces open condition 2's 09-30 cold figures and finds gates G-H2, G-H1 and
  G-detach met. The same day: the samples that set `cold.<mode>.ms` and `cold.bootfirst.ms` launch
  unattributed, as before the attribution, and `-cold-attribution` adds an attributed sample after each, with
  a `cold-attributed` record per mode that prints the attribution's cost; the 6.17 table counts the tip's own guest,
  so `fmod_ret`'s settled cold start reads 3.7 s, its settled `trace_proc` verification 3.0 s and its settled plane
  verification 0.23 s.
- 2026-10-19, R14 (supervisor R11c): `socket_connect` admits an approved abstract name's one connect from
  `tego_unix_approvals`, which the plane shares with `cgroup_net` by name; it refused it.
- 2026-10-17: R22 no longer lists a static non-PIE requirement as fallback-only:
  ADR 0021 (4) removed it from the fallback on 2026-09-29 (no linking check exists), and the shipped builds' static,
  non-PIE linking is a release choice for portability (docs/VERSIONING.md §5).
- 2026-10-17 (ADR 0022): §10.1's phase list names `prepare.rearm` and `prepare.rearm.start`, `Prepare`'s
  pass over the other builds' timers inside `prepare.lock-slot`.
- 2026-10-17 (ADR 0018 (7)): R14: `socket_create` does not see a socket turned into another family after it is made
  (`TCP_ULP`), and `cgroup/setsockopt`, beside it in every plane run, refuses that on every path.
- 2026-10-17 (ADR 0018 (7)): §10.1's `socket` check also measures `cgroup/setsockopt`
  (`setsockopt.excess.cgroup_ns`), and the warm start's phases include `attach`, the run's cgroup links and pins.
- 2026-10-16, revised 2026-10-17: §10's 200 ms budget for the plan at 1000 rows is asserted as
  written, one plan on the wall clock, in budget mode (`TEGO_TIMING_BUDGETS=1`: `scripts/timing-budgets.sh`, first in
  CI's bench-gate job on its own runner, and `make budgets`); every other run holds the fastest of five plans in the
  planning thread's own time (`testutil.MinOfThread`: the wall clock less the thread's waits for a CPU, the whole wall
  clock of a plan in which it blocked) to ten times it, 2 s, and its wall clock to a hundred times it (docs/BENCHMARKS.md,
  "Timing budgets in the test suites").
  It was one plan on the wall clock in every run, which a loaded machine could fail for the machine's sake; the first
  version of the unit gate (2026-10-16) held CPU time, which no wait reaches. A plan slowed by 250,000 rounds of a loop
  per row fails budget mode with the host as found (251 to 406 ms, 12 runs of 12) and in an idle 4-vCPU KVM guest (283
  to 512 ms, 22 of 22), and one slowed ten times more fails the unit gate under 16 busy loops in that guest (18.2 to
  21.4 s of own time, 4 runs of 4; with the first gate, 4.90 to 4.95 s of CPU time on the host, 7 of 7); the unmodified
  plan measures 1.6 to 6.2 ms in budget mode, and 2.0 to 13.8 ms of own time under the busy loops (three sweeps of
  28 runs, 2026-10-17). The budget is unchanged.
- 2026-10-16 (KVM root suites, default-lsm boot): R21's `ptrace_traceme` helper traces from its thread-group leader
  with every signal blocked. It had locked its goroutine to whatever thread it was on; under load that was now and
  then not the leader, the traced thread's exit left a zombie no pidfd wait reaps, and `doctor.Run` and
  `tego doctor --json` waited for the helper for 11 and 24 minutes until the suites' timeouts; and a Go runtime
  `SIGURG` stopped the traced thread for its tracer, so the cell failed and the mode was reported unavailable (58 of
  320 test runs of 40 tries under CPU contention, 0 of 440 after). *Rejected:* reaping the traced thread from doctor with a `__WALL`
  wait by thread id, which keeps a helper whose answer a signal can still stop; a timeout alone, which turns the hang
  into the same unavailable mode.
- 2026-10-06: what a mistaken revert dropped on 2026-09-30 is back, each piece checked against the code:
  §2.18 (the measured start and open cost; `bpf/include/maps.h` cites it); R20's pin-by-name rule with
  `TestPlaneRunAdoptsThePinnedPlane` and `TestAdoptedObjectsPinEveryMapByName`; §2.7's bprm_check sample through
  `tego_plane_own_sample` into a pinned `tego_plane_path_buf`; §2.15's ABI-gated truncate cell and the fenced walk's
  kill test 4 and guest runs; §2.17's `tego_modify_hook` (the spec named `tego_decide_remove`, `tego_create_hook`
  and `tego_truncate_hook`, which no source declares). The two Changes entries that went with them were: §2.18 and
  the batch lookups (`test/vm/matrix.sh` takes `VM_ONLY_LSM`), and the one sample writer
  (`TestPlaneSampleHasOneWriter`) with the one `tego_modify_hook`.
- 2026-10-06: R25, I9 and §10 say T11 built what they called planned: the kernel
  runner's bpflsm and plane-mode axes and its `parity` runner (`TestConformanceKernel`), with TIER3-PLAN's T11 row
  for what is not green. §2.15's condition 4 notes that §2.13's conditions 2 and 3 are closed (§2.19; exec rows per
  link). §2.11's condition 1 names the per-run record of which path decided, `run_start.net_guarantees.unix`.
- 2026-10-17, R10, R25: the `bpflsm` column composes the floor's directory rights
  for a rename and an unlink as well (a file-level write entry's own rename and unlink are `refused`, as the kernel
  refuses them with `EACCES`).
- 2026-10-17, R10, R25: the `bpflsm` column composes the Landlock floor's `REFER` for
  a link and a rename, asks `path_link`'s walks in the hook's order, names a link at a `deny_write` end by its target
  where the table holds fs notifications (the supervisor's R15c answers it first), and refuses `exec.anonymous` when
  the table does not compile for the plane, as every exec row.
- 2026-10-17 (ADR 0055): §9 names the residual of a mount made after the fill, which an
  adopted process can make, shown on the kernel by `TestPlaneRunWalksTheMountTreeAsItStands`; no row, hook or fill
  decision changes.
- 2026-10-17 (ADR 0055): §2.9 records the handle's report of the files its fs rows were
  written at (`Handle.PlaneKeyed`), which an adoption reads; no row, hook or fill decision changes.
- 2026-10-05: §2.20 records the governed-run cells of `ptrace_access_check`,
  `ptrace_traceme`, `key_permission` and `bpf`, with their conditions: Landlock's ptrace scope answers an attach out of
  the run before the plane in `lsm` mode; `key_permission` is per check and the contract's opt-in only; `bpf` and
  `key_permission` are reached by a governed run only with the test build's filter seam. R3 and R14 name the tests.
- 2026-10-06: R27 and §10.1's open condition 6 carry kill test 5's measurement of what an `fs.ask`
  entry costs at tiers cgroup and bpflsm (160 to 692 ms on the pip build, inside R7's allowance by its 1 s), and §10 lists
  the kill test among the guest tests; they said only that nothing stops notifying with an `fs.ask` entry.
- 2026-10-06: R28's arm64 row, §9 and §10 name `ci.yml`'s `build-test-arm64`, which runs the plane's tests
  on GitHub's arm64 runner as root (the plane's load and step A hooks, doctor, a plane run, the freeze and arming
  tests, the stress cell); the first log is not yet recorded.
- 2026-10-06: §2.15 records `TestPlaneSeqcountStress`, the stress cell for the directory walk's ordering and
  for the plane's refusals under renames, with an oracle unit-tested without root. §2.15's walk paragraph and
  conditions 1 and 2 describe the walk as built: the mount recheck and the fenced sequence reads landed on 2026-09-30
  and a later revert put the
  earlier text back, so the spec said "static subprogram", "not detected" and
  "no barrier" about a walk that is global, rechecks mounts and carries `tego_dir_fence`.
- 2026-10-05: §10.1: `PERF_KERNEL=<matrix row>` runs the guest perf suite on a row's kernel (`test/vm/perf.sh`,
  `perf_test.sh`), so the cold-start campaign can read the rows beside 6.17; a doctor-only row is refused. No budget moved.
- 2026-10-05: R28's table is measured per row and boot now: `make vm-matrix` keeps the plane mode tier cgroup decides
  by as `cgroup_mode` in summary.json (doctor's D7 clause, `test/vm/doctor-facts.sh`), with the Landlock ABI. The matrix gained
  `ubuntu-25.10` (6.17), `fedora-7.2` and the doctor-only `ubuntu-22.04`, whose ABI 1 offers no tier, so it selects no plane.
- 2026-10-05: §2.11 condition 1: a datagram `socket_sendmsg` would refuse is refused by
  the supervisor with `EACCES` and recorded once, without `best_effort`; the plane still writes no line of its own.
- 2026-10-27 (ADR 0043): §2.21: the fallback's listener refuses an open of a covered file
  (enforce-cgroup-observe R8); its supervisor's half stays in the "not built" list.
- 2026-10-27 (ADR 0043): R6: every clear of a slot (Detach, the purge, the reaper) deletes the slot's
  name map entries after the header and the kernel's clear; the reaper opens each pinned plane with its name map.
  §2.21's "not built" list loses the clears.
- 2026-10-17 (ADR 0043): §2.21: the name entries' kernel half (the name map with rows that sum their arms
  up, the 128-byte slot header with its flag and leads, the scope byte, the name check and the climb in file_open, the
  create, unlink and truncate hooks, path_link and path_rename, D5) and the backend's fill of the name map, behind
  `agent.NameEntriesEnforced`, which no product build sets; the build hash moves with the objects. R5's fourth inner
  map, R6's header, R7's second climb, R8's and R10's name checks are as §2.21 says. Every fs hook now reads its
  decision back through the task's scratch value before it records it (`tego_plane_settle`), path_mknod's
  socket-bind arm is a subprogram of its own that reads the floor from the task's record of the decision, and the
  record fallback's sample is a global function verified once per program: behaviour unchanged, fewer verified
  instructions, which the name check spends. path_rename tests whether its destination exists at run time
  (`tego_positive`): the verifiers of RHEL 9's 5.14, 6.8 and 6.12 take a trusted dentry's `d_inode` for never
  NULL and hard-wired path_rename's plain test of it in lsm mode, so a file moved into a stricter directory was
  refused (REFER's reverse arm) by the first name objects on those kernels, never by an object a run used. The
  load test (§2.3) logs each lsm program's verification time and prints `BUDGET OVER` over ADR 0043's limit of 6 ms
  on 6.17 without failing, which the base object already missed (§2.21's open condition). *Finding, not changed here:* `socket_listen`
  verifies 43,774 to 44,096 instructions on Fedora's 7.0 and 7.2, at base as with the name entries, over the plane's
  budget of 20,000 that `TestPlaneLoadsAndAttaches` and the step A and B cells hold, so those three fail on the Fedora
  rows for that program alone; on 6.17 it verifies 16,934 to 18,292.
- 2026-10-05 (ADR 0043): §2.21: the name entries' row model (scope rows and the scope-only kind,
  name rows, the name check, D5, compaction, the rule tag) built in `internal/policy/decide`, behind
  `agent.NameEntriesEnforced`; the kernel and the backend not built.
- 2026-10-05: §2.4 condition 7: `PlaneFDCap` gives a budget below its reserve a cap of
  0, not a negative cap `PlaneRows.FitFDs` read as unknown, which let selection give tier bpflsm to a run Prepare
  then refused.
- 2026-10-05: §2.20's records cover io_uring's bind and listen (fexit on `io_bind`/`io_listen`),
  whose refusals had no ledger line and whose marker misjudged the task's next socket mknod.
- 2026-10-05: §9 and §2.12's R12 state that a `deny_write` target's timestamps and inode flags are
  unprotected (no `inode_setattr` or `file_ioctl` hook).
- 2026-10-05: §1's two non-goal bullets, §2.1, §2.2 and R3 match the 28 hooks `bpf.PlaneHooks` holds:
  the network bullet names what stays excluded (inet `socket_connect`/`socket_sendmsg`/`socket_bind`) and the socket
  hooks the plane ships; `ptrace_access_check`, `ptrace_traceme`, `bpf` and `key_permission` are built, no longer
  E54 P1; `tego_plane_listen_rows` and the two new slot flags are listed; §2.20 records each new hook's fail-closed
  behaviour. Rewrites the unmerged 2026-09-30 non-goal change against the current hook list.
- 2026-10-05 (ADR 0023's acceptance note): §2.15's option (b) and §3's fill name the launcher's held O_PATH
  descriptors as ADR 0023's owned ones. They are bare numbers of the Landlock set until ADR 0023 C11b, when the
  fill takes one lease per planned descriptor before the iterator runs; until then R16's (mnt_id, ino) check is the
  only guard, and after it R16 stays as the re-verification ADR 0023 A5 requires.
- 2026-09-30: R19: a tier-cgroup table whose handed-over rows fail `choosePlane`'s second look is
  composed again without them before it falls back to the listener; it kept tier 1's plane-only relaxations.
- 2026-09-30: R20: a pinned plane link or program over maps since re-created is replaced, not
  adopted (it allowed every action), and a build whose plane directory cannot be removed keeps its maps.
- 2026-09-30: R21: a known-answer cell that failed with a transient errno (fork's ENOMEM,
  EMFILE) or gave no answer faults the mode, not cached; it failed the mode and was cached for the boot.
- 2026-09-30: R4 names every walk read that goes through the rdonly or probe-read
  reader, as ADR 0024 (9) does; it said CO-RE reads were for mount crossing only.
- 2026-09-30: §2.4 condition 7: selection asks Prepare's own check, so an auto table over the cap
  with its mounted-root rows, or with two fs entries on one inode, is given tier cgroup instead of being refused at
  tier bpflsm.
- 2026-09-30: R19: a tier-bpflsm table whose rows fail `choosePlane`'s second look is refused
  with `ErrPlaneCannotHold`; it fell back to the fanotify listener with an empty plane mode.
- 2026-09-30: R12: an unreadable mountinfo is `cgroup.ErrMountTable` for a table with a `deny_write`
  target, not a table keyed with no mount row.
- 2026-09-30: R8 and §2.7: `file_open` and `file_truncate` skip a private clone's file by
  its mount alone; the FMODE_BACKING test conjoined with it was dead code, and the bit is read by step C only.
- 2026-09-30: §2.5's kept known answers are read and kept by a run's plane probe only; doctor's own scope exercises every cell afresh (`TestPlaneKnownAnswersCacheIsForRunsOnly`).
- 2026-09-30: §2.5's cleanup rule covers a killed probe: the next probe (the plane
  probe's row or its known answers, or D8) sweeps its fixture directory.
- 2026-09-30: §2.14's decision is listed in the order the code takes it, the slot
  header's exec flag read before the task's scratch value, so a refused task-storage allocation never refuses a
  mapping in a run with no `exec:` section (`TestPlaneMapPolicy`).
- 2026-09-30: §2.7's exec image is made once per probe and shared by both sides.
- 2026-09-30: §2.7's exec image is one per probe, shared by both modes, not one per mode
  (`TestIntegrationPlaneProbeCopiesTheBinaryOnce`).
- 2026-09-30: §2.4 condition 6 records that `CompilePlane`'s path index landed; §2.5's
  probe syscalls are one per hook in `bpf.PlaneHooks`, each of which decides, not six with stubs passing; §2.5's cache
  entry is format 7, whose faulted plane answer keeps D7's and D8's half.
- 2026-09-30: §2.7 and R4: `path_unlink` and `path_rmdir`'s fmod_ret exit tests IS_PRIVATE on the
  directory, as their `security_path_*` wrappers do, not on the removed object.
- 2026-09-30: a truncated name is one `path-truncated` gap and never also a `dir-unresolved` one, in every fs
  recorder line (fexit and plane alike): the index was never asked (`TestPlaneTruncatedNameCountsOnlyPathTruncated`).
- 2026-09-30: §2.8's exec sample goes through the plane's one writer, `tego_plane_own_sample`,
  which sets every field; the exec copy left `dev`, `dir_ino`, `family`, `type`, `protocol` and `flags` holding an
  earlier record's ring bytes (`TestPlaneSampleHasOneWriter`). Unlink, rmdir, the creates and the truncates decide
  through one `tego_modify_hook`, the T9b fallback on both its refusal paths; the socket constants live in `common.h`.
- 2026-09-30: §2.5's LTO read: a config file with no `CONFIG_` line (empty, a stub) is no answer, so the next
  config and kallsyms are read rather than "no Clang LTO".
- 2026-09-30: §2.8 Ledger paragraph: `decision_plane` is `lsm|fmod_ret` with no plane fields on fanotify, and `exec-map` is a refused mapping rule, not a `plane_reason`.
- 2026-09-30: §2.12's `io_uring` paragraph: `enforce.Select` warns when tier cgroup's plane cannot hold the
  table, which then runs on the fanotify listener with io_uring refused.
- 2026-09-30: §2.17 records T9b, the record fallback: §7's fexit-recorder line and R23 built for every step A and step
  B hook a fexit wraps, I8 extended; the `tego_plane_recorded` mask (§2.2), `TEGO_EV_PLANE_FS` (23), the sample's
  `flags`; `TestPlaneRunEndToEnd`'s setfacl cell takes op xattr on 6.1; four conditions.
- 2026-09-30: E13's fs cap counts the net policy row the fs map also holds (`FSMapEntries`).
- 2026-09-30: §2.12's mount rows over the cap refuse a tier-bpflsm Prepare with the caller's
  `PlaneErr`, not a recompile without them.
- 2026-09-30: §2.14's map sample sets `path_ok` for a deliberately nameless file, so an unread name is no longer
  recorded as `anonymous` (the truncated path and a gap).
- 2026-09-30 (T14 follow-up): §2.14's condition 2 built: the `exec-map` compile warning (agent-contract E39), `compile
  --test`'s `exec.map` rows with the tier split, the `map-exec` conformance cells, kill test 4's pip `exec.allow` of its
  install directory; R26's warning half built.
- 2026-09-30: R6 gains the slot header (`tego_plane_slots`: gen, what the run decides, rows
  written; written last, zeroed first, read by every decided hook, refusing on another gen) in place of the exec and
  net policy rows, whose absence read as no section; the gen is the slot's epoch; Detach keeps a carried slot's rows;
  R8's backing skip needs the private clone too; the exec cap loses the policy row. P1's best-effort scratch value
  was not merged: T9b's record fallback already refuses and samples a task with none.
- 2026-09-30: R21 and §2.5 add the probe's known answers (a scratch slot through the real fill, nine cells, each
  an exact verdict and counter match) and `bpf/tests`' `bpf_loop` callback seed lint; the walk seeds `m` from memory.
- 2026-09-30: R19, R24, I7 and §2.8 record `run_start`'s `decision_plane` and the slot counters' gap lines at run end
  and at the reaper; R9, §2.9 and §11 record the one plane column composing the Landlock floor for a `#!` script
  (ADR 0019's 2026-09-30 note), whose conformance baseline entries are gone.
- 2026-09-30: §2.4 condition 7, the launcher's descriptor budget is the plan's cap (`landlock.FDBudget`,
  `PlaneRows.FitFDs`), refused naming it, never `EMFILE`, and an auto run the plane cannot hold is given tier cgroup
  (a pinned bpflsm still refused; §2.4's cap rule and §2.10 condition 2 amended in place); §2.6 and R16, the plan's
  identity is one statx per descriptor, the post-fill fdinfo pass is dropped, and the fill's config and templates are
  keyed by the launcher's tgid with the fill's gen, so fills and clears take no build-wide lock.
- 2026-09-30: R21's doctor wording: the plane's clause reads `decision plane: <mode> (...)` with the build as a short hash, the `lsm` FAIL is scoped to tier 3, and the boot fix is per distribution family; goldens for the fanotify-fallback, lockdown-without-`bpf_rdonly_cast` and no-`bpf_loop` boots.
- 2026-09-30: §10.1 records the perf budgets and the guest suite (`make vm-perf`); a later run adopts the plane's objects (`bpf.KernelOnlyMaps`), the kernel BTF is read once per process, doctor's plane clause names the fanotify fallback's scaling; five conditions.
- 2026-09-30: §2.14 records T14's step C: `mmap_file` and `file_mprotect` in `decide_stepc.h` (ADR 0027 as amended:
  the effective prot in both hooks, fmod_ret computing `mmap_prot()`; execmem and execmod; anonymous files by
  `exec.anonymous`; a write row's files by `bprm_check`'s three arms; S_PRIVATE inodes anonymous memory; 6.8+ overlay
  mappings from the user path), their own refusal sample (`TEGO_EV_PLANE_MAP`, a `refused` line), and R27's memfd
  half (`landlock.Run.PlaneMaps`); R3, R4, R23, R26 and R27 name their built half; four conditions.
- 2026-09-30: §2.15 records the recorder naming a plane run's path-hook records by the parent directory's path,
  walked in its fexit (`tego_dir_walk`; `bpf_d_path` and userspace resolution weighed and rejected), which opens
  T16's gate; `record: full` drops the mutations but the open family; an end outside every entry is the ruleset's
  refusal; R27 amended; four conditions. Kill test 4 pip timed with the drop on.
- 2026-09-30: §2.13 records T16: the filter's per-hook notification drop and its gate on a recorder that names path
  hooks (not enabled: condition 1); the exec hand-over not built (condition 2); R22 and R27 carry it.
- 2026-09-30: R3 headed built for steps A and D (T15), B and C not built (T13, T14), as R14 already says.
- 2026-09-29: §2.11 records T15's step D: `socket_connect` and `socket_sendmsg` (not `unix_stream_connect` and
  `unix_may_send`) decide unix names below 6.7 by the socket's cgroup, from `tego_unix_names` and a per-slot policy
  (`tego_plane_unix_policy`), loaded only where `connect_unix` is absent; R14's step D half built; R23 amended (no
  sample); two conditions.
- 2026-09-29 (6.1): R7's BOUND held on AL2023's 6.1 only once the walk's counters start from the
  caller's zeroed `tego_plane_hit` instead of constants: a verifier before 6.8 verifies a `bpf_loop` callback once,
  from its first call's state, and hard-wired the BOUND branch away (`TestPlaneStepAHooksDecide`'s bound cells;
  `TestPlaneWalkFailsClosed` holds the start).
- 2026-09-29: §2.7's walk bound is `bpf_loop(130)`, as R7 and the code say.
- 2026-09-29: E13's exec cap counts the policy row and the bare-name rows the exec map also holds.
- 2026-09-29: R11 and §2.4 key a `deny_write` target declared through a symlink at the link's own
  inode too (`PlaneRows.NoFollow`).
- 2026-09-30: R9 and R11 name their new kernel cells (an unhashed image's exec, the symlinked deny_write target, `path_rmdir`'s refusals).
- 2026-09-29: §2.12 records T13, Step B: R12, R13, R14's socket half, R3 (steps A and B) and R23 for step B built
  with their tests; `PlaneProtected` and `PlaneMountOnly` kind bits, the mounted-root rows, the net policy row and
  the optional hooks; §2.7's condition 1 (overlay copy-up) settled by the private-clone skip; `io_uring: true`
  admitted at tier cgroup with a plane mode (ADR 0018 (5)); `DecisionPlaneReporter` wired in the backend;
  §6 cases 4, 5, 8 and 14 built; six conditions found.
- 2026-09-29: R7's walk crosses a mount without a step (ADR 0024's walk-review note) and its BOUND and
  UNRESOLVED refusals are tested; §3 and §2.4 condition 1 follow; R3 and R4 headed built for step A.
- 2026-09-29: §2.10 records T7: tier `bpflsm` as the tier-2 backend with the plane required in LSM mode
  (`bpflsm.New`, `cgroup.Options.Tier`), built with the objects, selected through `enforce.LSMPlane` from doctor's
  `PlaneFor`, refusing at Prepare what tier cgroup runs on the listener; a run's probe scope at reach `bpflsm`; R19,
  I7 and §6 cases 12 and 13 built; two conditions.
- 2026-09-29 (tier 2): R6's stale rows are no longer counted (`tego_plane_counts.stale` removed);
  §2.8's refusal sample builds its path in task storage, not a per-CPU buffer (`TestPlaneKeepsNoPerCPUScratch`).
- 2026-09-29: §2.8 records T9's record: R23, R24 and I8 built for step A; §2.7's condition 2 resolved (bit 16);
  kernel reason code 12 `identity-mismatch`; `plane_reason` beside the closed-set reason; exec lines at tier 3 are
  the kernel's (supervisor R7a amended); four conditions.
- 2026-09-29: §2.9 records T6: the plane in tier cgroup's backend (load and adopt under `<hash>-<mode>`, slot maps
  once, the fill from the Landlock plan's descriptors with neutral rules, the policy and name rows, arming with the
  run's mode in `tego_run.plane`, no fanotify group, the clears, the answer pin, the build's removal of its planes);
  R5, R6, R15 to R18, R20, R21, R22 (the listener's half), I5 to I7 and §6 cases 1, 2 and 11 name their built half;
  two conditions found.
- 2026-09-29 (T12): header, R3, R4, R12 to R14, R19, R22, R25 to R28, §6 and the invariants carry their built state and, for the rest, the ticket that builds them (T7, T11, T13 to T16); §10 and §11 updated.
- 2026-09-29: R25 records T10's `compile --test` bpflsm column (`PlaneEvaluator`), the CAPABILITIES golden pair and the conformance bpflsm expectations.
- 2026-09-29: created (TIER3-PLAN T12), all rules plan-only.
- 2026-09-29: §2.2 carries the T2 layouts; §2.3 records the T2 skeleton (no rule built).
- 2026-09-29: §2.4 records T5's row compiler: complete rows, `kind` bits, `rule_idx` as the row's position, exec rows,
  neutral rules, the cap as a compile error at bpflsm, and six conditions. R5, R10, R11, R17, R25 and E13 name their
  built half; R11 restated (rename of the ancestors up to the outermost write entry; rmdir needs no bit).
- 2026-09-29: §2.6 records T4's fill (`decide_fill.bpf.c`, `planefill.go`): the fill and clear programs, the plan, the
  fdinfo check, the filler, the timings on 6.17, RHEL 9.8 5.14 and AL2023 6.1; R16 built, R6's fill half built;
  §2.4's condition 4 built; §11's unscoped question answered.
- 2026-09-29: T8 built doctor's half of R18, R19 and R21 (§2.5); R21 and R28's lockdown row follow ADR 0024's T0
  note (no mode under confidentiality only without `bpf_rdonly_cast`; `bpf_loop` required).
- 2026-09-29: §2.7 records T3's Step A bodies over §2.4's rows; R1, R2, R7 to R11, I1, I2, I4 (step A) and §6 cases 2
  and 3 built with their tests; exec rows gain `flags`, a policy row at key 0 and name keys; kernel reason codes 10 and
  11; two conditions found (overlay copy-up, an exec by directory recorded as a row).


### C40 implementation amendment — 2026-11-03

ADR 0113 adds the mandatory `unix_may_send` hook beside the older raw-name hooks of §2.11.
It looks up the current run, validates its slot generation and immutable-floor flag, then checks the
kernel's actual bound peer path, protected parent/name guards, multiple-link refusal and the nearest
FS row's `TEGO_ROW_BUILTIN_IPC` bit. An own-runtime guard stops before outer refusals; exact SSH and
explicitly allowed container peers have a peer-only exception tag. Those tags never lift filesystem
mutation protection. Thus an admitted datagram redirected through a pre-existing alias still meets
the built-in floor. This does not change ordinary contract net-policy guarantees for unlisted peers.
Its named refusal sample becomes an ordinary net/sendmsg line carrying `builtin.host_ipc` or
`builtin.tego_surface`; map sizes are unchanged and adoption uses the changed object hash. The existing FS-row and fill-template `pad2` field carries bit 0 for ledger ancestry; it is copied into the walk hit, so only `ask.sock`/`operator.sock` are refused beneath a custom or shared ledger root. It does not become a whole-directory IPC refusal.
The tty slot flag also delegates default terminal write opens to the independent Landlock tty layer;
explicit protected/read-deny rows retain priority. No per-pty row is installed.
