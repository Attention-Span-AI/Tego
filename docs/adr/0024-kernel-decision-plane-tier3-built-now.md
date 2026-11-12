# ADR 0024: build the BPF LSM tier now, as a kernel decision plane that tier 2 also runs without a boot change

Status: accepted 2026-09-29, as amended by T0's measurements. Built through T16 on 2026-10-04: steps A to E, the fill, mode probe, Tier 2/3 wiring, compile column and record fallback. Exec handover now delegates decisions and terminal outcomes when complete live kernel recording is available, with metadata notifications retained and supervisor fallback otherwise (enforce-plane §2.19). Dated matrix and performance evidence remains tied to its recorded binary/kernel. Proposed 2026-09-23. Amends ADR 0002 and ADR 0011; identity is ADR 0025. FEATURES E8 moves from P1 to P0 for this hook set; E54's remainder stays P1.
Amended in part by ADR 0048 (accepted 2026-10-06; P2 built 2026-10-19 and in verification, its acceptance not met): bprm_check gains the exec-pin steps, a `tp_btf/sched_process_exec` program and three maps join the plane, and its ptrace hooks refuse an argv-guarded target ((5), (11)).

Decision:
(1) One CO-RE object, bpf/decide.bpf.c. Each hook body is written once and exposed twice: SEC lsm/<hook> (BPF_LSM_MAC) and SEC fmod_ret/security_<hook> (BPF_MODIFY_RETURN). The ancestry walk is one global subprogram, walk(dentry, vfsmount, run_idx, gen), verified once per program: its pointer arguments reach it as scalars through a per-CPU slot, and its body is bpf_loop(64, step), whose callback climbs one level (d_parent, or mnt_mountpoint and mnt_parent at a mount root) and does that level's one row lookup, with the walk's state in a stack struct (T0's form d). It is bounded to 64 steps, with a mount crossing counting as one; a disconnected dentry or an exhausted bound refuses with path-unresolved. The walk returns an int; an lsm program maps it to 0 or -EACCES before returning (the LSM return range rejects the unmapped int), and fmod_ret programs do the same under (7). The plane needs bpf_loop in the kernel's BTF (5.17+, or a backport such as RHEL 9.8's); a kernel without it gets no plane mode from the probe.
(2) Modes. LSM mode where bpf is an active LSM; fmod_ret mode otherwise; the fanotify fallback where neither passes the probe. The machine setting bpf.plane (auto | lsm | fmod_ret, /etc only) pins a mode for operators and for ADR 0017; auto prefers LSM mode. fmod_ret mode is not offered on a kernel whose config shows Clang LTO (CONFIG_LTO_CLANG), where a security_ function can be inlined at a call site. The mode is part of the build's pin directory name, so two modes never share maps.
(3) Probe. doctor's mode probe loads the mode's full hook set. In a scratch cgroup it performs a scoped refusal through at least one syscall per hook, and outside the cgroup a matching action that must pass. A mode is selected only when every hook counted. The probe also checks BTF presence, bpf_loop and bpf_rdonly_cast in BTF (which pick the object build, (9)), and the 6.1 prototype (argument count) of every security_ and bpf_lsm_ function used. The result is cached per boot and build in the run-probe cache (runcache.go), together with D6's functional LSM check, and written to the build's pin directory, so a run that adopts a pinned build runs no probe.
(4) Tiers. bpflsm is the plane in LSM mode and needs bpf active. cgroup is the plane in the probe-selected mode, else the fallback. auto takes bpflsm where it can. Tiers 2 and 3 enforce one semantics: SEMANTICS §2's nearest-wins walk and §4's exec rule, intersected with the inherited tier-1 Landlock ruleset. SEMANTICS §4's 'allowed in tier 3 when its interpreter is allowed' is withdrawn, because tier 3 also installs Landlock, whose EXECUTE rule refuses an unlisted script. The capability line records decision_plane: lsm, fmod_ret or fanotify, and reports deny_read nested in a write entry as enforced at tier 2 only once step A is loaded.
(5) Hooks, in landing order.
- A:
  - file_open: read and write decisions only. Exec rows are never applied here, so PT_INTERP's open of ld.so needs no exec row, and a directly invoked loader is decided by bprm_check.
  - bprm_check_security: exec by inode and name, and anonymous images; exec is decided only here.
  - path_rename and path_link: SEMANTICS §2's REFER rule, refusing when the source's nearest entry is more restrictive than the destination's. This also stops a deny_read file being renamed or linked out of its tree.
  - path_unlink and path_rmdir.
  - R15c's ancestor rule in the kernel: renaming, unlinking or removing a deny_write target, or any directory between its write entry and the target, is refused, using ancestor rows.
- B:
  - path_mknod (in may_o_create, before an O_CREAT create makes the inode), path_mkdir, path_symlink, path_truncate, and file_truncate where the kernel has it.
  - path_chmod, path_chown, inode_setxattr, inode_removexattr, and inode_set_acl and inode_remove_acl (6.2+).
  - socket_create: ADR 0018's allowlist for every family; kern != 0 returns 0.
  - The dentry-only inode_ hooks walk d_parent within the superblock. Prepare keys a row on every mounted root at or below a deny target (from mountinfo), so that walk always meets it. A walk that reaches a superblock root with no row returns 0: these hooks exist only to protect deny targets, since Landlock governs no chmod, chown, xattr or ACL.
- C: mmap_file and file_mprotect, with ADR 0027's policy.
- D: unix_stream_connect and unix_may_send, where connect_unix is absent (below 6.7).
E54's remainder follows as P1: ptrace_access_check, ptrace_traceme, bpf, socket_bind, socket_sendmsg, and key_permission, whose security_ function exists (this corrects GAPS C32). Network stays on the per-run cgroup programs and the supervisor.
(6) Scoping. Programs are global: each does one run_set lookup on bpf_get_current_cgroup_id() and returns 0 on a miss (R2, I1). file_open does not decide files the kernel opens for a stacking filesystem (FMODE_BACKING, 6.6+), because the user's own open of the overlay file was already decided.
(7) A decision returns 0 or -EACCES and nothing else (SEMANTICS §5). The verifier leaves BPF_MODIFY_RETURN unbounded, so this is a unit-tested rule of decide.bpf.c. The fanotify EPERM exception and tier 3's designed EPERM for exec both end.
(8) fmod_ret runs at the entry of the security_ function, so each body reproduces what the wrapper does before the chain. Path hooks return 0 for an IS_PRIVATE inode, as security_path_* do. mmap_file computes the effective prot as mmap_prot() does: READ_IMPLIES_EXEC on a mount that is not noexec adds PROT_EXEC.
(9) Every hook argument is read with direct BTF loads. The walk's reads of kernel objects (d_parent, the mount crossing, the identity fields of ADR 0025 (4)) go through bpf_rdonly_cast where the kernel's BTF has that kfunc (6.2+, and backports such as RHEL 9.8's), else through CO-RE bpf_probe_read_kernel. These are two builds of decide.bpf.c, the rdonly build and the probe-read build, and the probe picks one from BTF: a program naming a kfunc the kernel lacks fails to load, weak or not. lockdown=confidentiality refuses bpf_probe_read_kernel at load on every kernel, 6.17 included, so under it only the rdonly build loads, and a kernel without bpf_rdonly_cast (AL2023 6.1) has no plane mode under confidentiality. The gate is the kfunc in BTF, not the kernel version.
(10) Arming. The run's run_set row is inserted after the child stage's first execve has returned and before the ack, the same arming point as ADR 0021's marks. The stage's exec of the tego binary therefore meets no row and needs no admission, and the agent cannot exist before the row.
(11) Record. A decision leaves its rule_idx in a task-storage map, which tracing programs can use (present in 5.14's bpf_trace.c). ADR 0016's fexit programs read it; they exist on file_open, path_mknod, path_mkdir, path_rmdir, path_unlink, path_rename, path_link, path_symlink, path_truncate and file_truncate. On every other hook (bprm_check, chmod, chown, the xattr and ACL hooks, mmap_file, file_mprotect, socket_create and the unix hooks) the plane emits its own refusal sample. It never emits one on a hook that has a recorder fexit. In fmod_ret mode each fexit shares the plane's trampoline; in LSM mode it is a second trampoline.
(12) Lifetime is ADR 0022's; slots and rows are ADR 0025's and 0026's.
(13) At tiers 2 and 3, once step C is loaded and probed, the seccomp arm that refuses every memfd_create where the kernel lacks MFD_NOEXEC_SEAL is dropped, because bprm_check and mmap_file refuse anonymous images race-free. The MFD_NOEXEC_SEAL arm stays as defense in depth; tier 1 is unchanged.
(14) Step E. With steps A and B loaded, ADR 0026 in place and ADR 0016's producer table live, the filter inherited at tiers 2 and 3 stops notifying write-opens and fs mutations, unless the contract has fs.ask entries (P1). The plane decides those actions race-free and the kernel records them.
(15) Stated residuals.
- In fmod_ret mode a refusal skips the other LSMs' hooks for that access, their audit included.
- Root outside the run can detach the plane, as it can every tier-2 program. Root inside the run is ADR 0033's.
- If a kernel drops the security_ exemption, fmod_ret mode fails at load and the probe falls to LSM mode or the fallback, never to silence.
- arm64 is unmeasured: until an arm64 row runs ADR 0017, the probe decides there and the fallback is expected.

Why: [measured, guests booted with each kernel's own lsm list] fmod_ret programs on security_file_open, security_bprm_check, security_mmap_file and security_path_unlink refused inside one cgroup and allowed outside it, 1000 of 1000, on 6.17, Ubuntu 24.04's 6.8 (no bpf in lsm), RHEL 9.8 5.14, AL2023 6.1 and 6.12, Debian 13 6.12 and Fedora 7.0. A real lsm/file_open program and a BPF_LSM_CGROUP deny attach on the Ubuntu kernels and never run (0 of 1000), as ADR 0002(b) states.
Cost per open:
- A trivial LSM program: +0.12 to +0.21 µs on 5.14-6.17.
- A trivial fmod_ret program: +110 to +277 ns.
- The in-run walk at depth 9: +180 to +510 ns.
- For comparison, a fanotify round trip is 13-19 µs for an allowed open and 47-59 µs for a refused one, paid by every process on a marked mount.
The 32-level walk with direct loads loaded under confidentiality on 6.17 and 5.14.
[measured] Per host call, with the full set plus the fexit recorder and the lookup missing:
- Open: +197 ns (fmod_ret) or +222 ns (LSM) on 6.17; +218 ns on 6.8; +236 or +308 ns on 6.1.
- mprotect: +76 to +118 ns.
- 5-op fs iteration: +1.2 to 1.5 µs.
- compileall: within ±2%.
- Every hook loads on RHEL 9's 5.14, file_truncate included; only AL2023 6.1 lacks file_truncate.
- Cold attach plus removal of 21-22 links: up to 1.81+1.81 s (6.8, RHEL 9 fmod_ret), 2.29+2.29 s (RHEL 9 LSM), 0.02+3.7 s (6.1 LSM).
[documented, master verifier.c, checked today] check_attach_modify_return admits any security_ function in both CONFIG_FUNCTION_ERROR_INJECTION branches; check_return_code leaves BPF_MODIFY_RETURN unbounded.
[documented, mainline] may_o_create calls security_path_mknod before the create; security_mmap_file hands the hook mmap_prot(file, prot); security_path_unlink returns 0 for IS_PRIVATE; fanotify_release allows pending events.
[documented, fs/open.c v6.6 and fs/backing-file.c v6.8, checked today] Overlay real files reach security_file_open in the agent's task; on 6.2+ setfacl goes through security_inode_set_acl and rewrites the mode without security_path_chmod.
[documented, kernel/trace/bpf_trace.c v5.14, checked today] Task storage is available to tracing programs, so no BPF LSM dependency.
[documented, LWN 813724] The security_ exemption was called a stopgap in 2020 and is still in mainline.
[inference] With file_open alone, rename or link out of a nested deny_read tree bypasses it, and without the ancestor rule 'mv .git .git.old; mkdir .git' yields unprotected hooks once item 14 stops the notifications.
[inference] Every fanotify hazard exists because the decision is made in a stoppable userspace process, or after the object exists; the plane removes both.

Security argument: Fail-closed by construction:
- The decision is made in the kernel on the object the kernel resolved (bprm->file, the path hook's dentry, the opened file), so there is no time-of-check gap. The supervisor's exec, deny_write and loader races (C30 a and b, C31, R15c) close.
- The plane only refuses. Returning 0 hands the call to the rest of the chain, so a plane bug that admits too much falls back to the inherited Landlock floor, and one that refuses too much fails closed.
- Its state outlives the launcher: pinned programs, rows held by the run's Landlock domain (ADR 0025), a build never removed while a row exists (ADR 0022), and links pinned (ADR 0020). A stopped or killed launcher changes nothing the plane decides.
- A mode that does not load, or in which any hook fails the scoped probe, is never used silently. The run gets another mode, or the fallback with its capability line, or a refused Prepare when the contract pins a tier that needs the plane.
- Protected names cannot be moved or replaced out from under their rules: REFER for deny_read, ancestor rows for deny_write.
- Host processes pay a lookup and are never decided. Kernel-internal opens for stacking filesystems are not re-decided on a path no rule names.

Options considered: Chosen: the plane in two attach modes, with fanotify as the probe-selected fallback.
Rejected:
- Keep fanotify and close only E39: E15, E16, E34, E35, E37 and E40 stay, every open on a marked mount pays 13-59 µs, and the exec, deny_write and loader races stay.
- Tier 3 only as designed (BPF_LSM_MAC gated on lsm=): absent on Ubuntu 24.04, 25.10 and 26.04, stock WSL2 and hosted CI, and a second decision path.
- fmod_ret mode only: concentrates the exemption's upstream risk where the documented interface exists.
- BPF_LSM_CGROUP: 10 hooks host-wide, needs bpf active, and cilium/ebpf v0.22 cannot load it.
- kprobe decisions: cannot override a return value.
- stage_pending admission in the kernel: a second arming point and admission code keyed on the launcher's binary identity; arming after the stage's exec needs neither.
- A tid-keyed hash for the scratch: an update and a delete per decision; task storage works for tracing programs.
- Probing file_open only: an inlined or bypassed security_ function would go undecided without notice.
- Step A without rename, link and unlink: nested deny_read is bypassable by rename or link.
- fexit on every plane hook for a uniform record: doubles LSM mode's trampolines for hooks Landlock never refuses, where the plane's own sample is exact.

Consequence: Wherever a plane mode loads, tier 2 closes E15, E16, E17, E24, E34, E35, E37, E39 and E40. The static non-PIE constraint, the fanotify quotas, the stage exemption and ErrStage* go, and refusals read EACCES in every tier. At tiers 2 and 3, C30 (a) and (b), C31's loader, R15c's deny_write (ancestors included) and the memfd floor below 6.3 close race-free, and GAPS B1 leaves the critical path. tier cgroup and tier bpflsm become equal in what they enforce; bpflsm is the documented interface to choose where the boot line allows.
While a build is attached, every host open, exec, mmap and path operation pays a lookup. The measured costs per mode are published in CAPABILITIES and doctor, and ADR 0022 bounds them in time. LSM mode and fmod_ret mode cost the same per open within 130 ns either way (P7's raw open loop on 6.17: fmod_ret minus lsm -105 to +128 ns; the earlier +25 to +72 ns for LSM is below that resolution, and a python probe's +2 us for fmod_ret did not reproduce), and LSM mode costs about 0.5 s more cold attach and removal on RHEL 9, because the recorder's fexit cannot share the bpf_lsm_* trampoline.

Implementation plan:

Prerequisites on master: ADR 0017 (the suite, both modes on bpf-active rows), 0020, 0022, 0023, 0026, 0016 steps 2-3, 0033, 0034.
Step A (L), one landing unit with ADR 0025 and ADR 0028 S4:
- bpf/decide.bpf.c: shared bodies, both SEC variants, the global bpf_loop walk and the 0/-EACCES discipline, generated per byte order and per reader (rdonly and probe-read, (9)) in internal/bpf/gen.go.
- enforce/cgroup plane.go: load one mode; adopt pinned objects (mode in the pin directory name); arm the row after the stage's exec (internal/runtime run.go: WaitNotifyFD, Arm, Ack); rows from the core.
- internal/doctor plane.go: the per-hook probe, the BTF, prototype and LTO checks, the runcache entries and the mode file.
- enforce/select.go, pkg/spec/backend matrix.go and spec/backend/CAPABILITIES.md: decision_plane and the deny_read-nested row, as one golden pair. Tier bpflsm becomes Buildable. spec/config/v0 gains bpf.plane. Prepare places no fanotify mark when a plane mode is selected.
- Tests:
  - Unit tests of the return discipline and the row compiler.
  - As root in GUEST (6.17 with bpf active: LSM mode by default, fmod_ret via bpf.plane) and on MATRIX (both modes on every bpf-active row): each hook refuses in the run and allows outside it and in another run.
  - REFER cells: rename and link of a deny_read file out of its tree are refused.
  - deny_write ancestor cells: mv .git .git.old is refused.
  - Exec cells: a direct loader is refused unless listed; PT_INTERP loads; memfd exec is refused.
  - SIGSTOP and SIGKILL of the launcher mid-run: an open under a deny_read beneath a write entry stays refused, and host opens are unaffected.
  - lockdown=confidentiality boots of 6.17 and 5.14.
  - An overlayfs mount under a write entry: writes work, with one line naming the user path.
  - Kill tests 1, 4 and 7 at tier cgroup on MATRIX; the overhead benchmark rows.
- Measure: the load and verify time of decide.bpf.c with the walk in every hook on 5.14 and 6.1; cold attach and removal at the final trampoline counts per mode on 6.8, RHEL 9 and 6.1; the idle memlock of a lingering build.
Step B (M): item 5B's hooks, the mounted-root rows, and socket_create with io_uring: true admission (ADR 0018 PR 3). Tests:
- A refused create leaves no file.
- The TOCTOU cells (a thread swapping a symlink during a deny_write decision) pass.
- setfacl -m u::rwx, chmod, chown and setxattr on a deny_write target are refused, including on a tmpfs mounted below a deny target.
- An io_uring AF_VSOCK socket is refused under io_uring: true.
Step C (M): ADR 0027, then item 13, with step C probed before the memfd arm is dropped.
Step D (S): the unix hooks, with conformance cells on 5.14 and 6.1.
Step E (S): item 14, measured on kill test 4's pip kind.
Docs:
- A new docs/p0/enforce-plane.md, the normative spec with PLN-* rule IDs (ADR 0030).
- ARCHITECTURE §2, §10, §11 and §14: the mode per row, and the host-cost table per mode and kernel.
- SEMANTICS §2, §4 and §5; REASON-CHANNEL item 1.
- enforce-cgroup-observe: E15-E40 marked fallback-only.
- GAPS B1, B6, C30, C31 and C32.
- FEATURES E8 (P0 minimal), E9b (condition) and E54.
- CAPABILITIES and doctor: the cost table.

*T0 spike, 2026-09-29 (measured; the walk's form, TIER3-PLAN §3 "Verifier plan"):* prototypes in `bpf/spike/walk.bpf.c`
with the loader `tools/spike/walk` (a spike, built only with `-tags tegospike`, never embedded), run as root in the
KVM guest (2 vCPU, 2G) on 6.17.0-41-generic (lsm= plus bpf), RHEL 9.8's 5.14.0-687.49.1 and AL2023's 6.1.186 (each
kernel's own lsm list, both with bpf), each also booted lockdown=confidentiality; raw output in
`tools/spike/walk/results-2026-09-29.tsv`. Every form is the same walk: d_parent to a mount root, then
mnt_mountpoint/mnt_parent, 64 steps at most, a crossing one step, one lookup per step in the slot's inner rows map
(HASH_OF_MAPS by run_idx, inner keyed by `struct inode *`), a row of another gen counting as absent, identity
(i_ino, i_generation, s_dev) checked on a hit. Four programs per form: lsm/file_open, fmod_ret/security_file_open,
lsm/path_rename and fmod_ret/security_path_rename (these walk both ends: two calls). Forms: **a** global
subprogram over u64 addresses with a plain bounded `for`; **b** the same loop `__always_inline`; **c** one
`bpf_loop(64, step)` whose walk is inlined; **d** `bpf_loop` inside a global subprogram. Each with two readers:
**rd** `bpf_rdonly_cast` loads, **pr** CO-RE `bpf_probe_read_kernel`. The global forms take their pointers as
scalars laundered through a per-CPU array slot (root may store a pointer into a map value; a load back is a
scalar), so no caller needs a probe read.

Verified instructions (file_open / path_rename) and the kernel's verification time, lsm file_open, minimum of 5 loads:

| Form | 6.17 | RHEL 9 5.14 | AL2023 6.1 |
|---|---|---|---|
| a-rd | 217,385 / 217,409; 293 ms | 35,855 / 35,879; 24 ms | reject (no bpf_rdonly_cast) |
| a-pr | 16,338 / 16,362; 16 ms | 19,074 / 19,098; 8.7 ms | 18,899 / 18,923; 19 ms |
| b-rd | 249,747 / 573,502; 335 ms (rename 803 ms) | 36,544 / 81,586; 21 ms (59) | reject |
| b-pr | 65,901 / 126,925; 53 ms (107) | 57,022 / 113,811; 35 ms (110) | 57,280 / 114,307; 41 ms (88) |
| c-rd | 808 / 1,603; 6.0 ms | 741 / 1,469; 3.1 ms | reject |
| c-pr | 1,562 / 3,171; 7.6 ms | 2,404 / 4,857; 7.2 ms | 370 / 725; 0.6 ms |
| **d-rd** | **822 / 846; 4.6 ms** | **757 / 781; 4.6 ms** | reject |
| **d-pr** | **631 / 655; 5.1 ms** | **872 / 896; 5.6 ms** | **391 / 415; 0.6 ms** |

fmod_ret verifies the same instruction count faster (d forms 0.7-1.3 ms). The wall time of a load adds a fixed
35-66 ms that a 55-instruction fentry program pays too (attach-target resolution in the loader), so a whole
decide.bpf.c set costs that per program on a cold build, whatever the form; a pinned build pays none.
Per call, the kernel's own run time per invocation (bpf_stats), a 13-step walk with one mount crossing and no row
hit, in the governed cgroup / outside it (the run-set miss), lsm file_open, quiet 6.17: a-rd 418 / 85 ns, b-rd
622 / 103, c-rd 464 / 76, d-rd 461 / 74, a-pr 1,803 / 142, b-pr 1,487 / 118, c-pr 855 / 74, d-pr 763 / 76; fmod_ret
d-rd 461 / 73, d-pr 801 / 65; lsm path_rename (two walks) d-rd 804 / 67, c-rd 802 / 71. RHEL 9 and AL2023 spread
more between repeats (rd 295-1,288 ns, pr 449-2,776; misses 43-302 ns), and the wall-clock loop (a Go open+close
at 2.3-3.5 µs bare) moved by the same order between repeats, so only the order stands: rdonly loads cost about
half of probe reads per walk, and form does not matter beyond that. Wall, quiet 6.17, d-rd: +840 ns (lsm) and
+780 ns (fmod_ret) per open in the governed cgroup, +270 to +400 ns outside. Every program that loaded, on every
row: a deny row on a directory refused a governed open seven levels below it (EACCES), the same open outside the
cgroup passed, a row whose gen was not the run's was walked past, and the in-kernel clear removed it.
- An lsm program that returns the global walk's int unchanged is rejected (the LSM return range); fmod_ret accepts
  it. The caller maps the walk to 0 or -EACCES, which (7) requires anyway.
- **Lockdown=confidentiality refuses `bpf_probe_read_kernel` at load on all three kernels, 6.17 included** ("program
  of this type cannot use helper bpf_probe_read", 5.14 and 6.17; "unknown func" on 6.1). (9)'s "below 6.2" is wrong:
  under confidentiality only the rd forms load, on 6.17 and on RHEL 9.8, whose BTF carries the backported
  `bpf_rdonly_cast` and `bpf_loop`. AL2023 6.1 has no `bpf_rdonly_cast`, so under confidentiality it has no plane
  mode, as (9) concluded for below 6.2; the gate is the kfunc in BTF, not the version.
- A weak `bpf_rdonly_cast` the kernel lacks rejects the program ("invalid func unknown#..."), so the rd and pr readers
  are two builds of the object, selected by the probe from BTF.
- (2)'s LTO check: CONFIG_LTO_NONE=y on all three (6.17's /boot/config, the RHEL and AL2023 packages' config), and no
  `.llvm.` symbol in any row's kallsyms. security_file_open and security_path_rename are in each row's BTF, and
  fmod_ret loaded, attached and refused on all three; lsm programs ran on all three with bpf active.

**Recommended form: d.** The walk is one global subprogram, `walk(u64 dentry, u64 vfsmount, u32 run_idx, u32 gen)`,
fed through the per-CPU laundry slot, whose body is `bpf_loop(64, step)` with the walk state (inner map, dentry,
mount, mount root, gen, result) in a stack struct. Reads through `bpf_rdonly_cast` where the kernel's BTF has it
(6.17, RHEL 9.8; the only reader under confidentiality), CO-RE probe reads otherwise (AL2023 6.1). It verifies in
391-896 instructions per program, rename's two calls included, in at most 6 ms per lsm program, against 16k-573k
instructions and up to 0.8 s (b-rd rename, 6.17) for the plain loop; per walk it costs what the fastest loop form
costs with the same reader. Rejected: a and b with rdonly loads (0.3-0.8 s of verification per program on 6.17, a
cold decide.bpf.c set of 20 programs in the tens of seconds); b-pr (53-110 ms each, 2x the per-call cost); a-pr
(loads everywhere without lockdown, 16-19k instructions, 9-19 ms, but no reader under confidentiality and 2-4x
d-rd's per-call cost); c (the same as d, twice the instructions on rename and link). Condition: `bpf_loop` is 5.17+
(RHEL 9.8 backports it); a kernel without it in BTF gets no plane mode from the probe. (1)'s "global subprogram,
verified once per program" stands; T1 amends (1) and (9) with this form and the lockdown finding (done, see the
next note).

*Amended 2026-09-29 (T1, TIER3-PLAN §11; accepted):* T0's findings are folded into the decision text above, which
was wrong in two places. (1) now names the walk's form (d: one global subprogram whose body is `bpf_loop(64,
step)`), the lsm program's mapping of the walk's int to 0 or -EACCES, and the condition that the kernel's BTF has
`bpf_loop` (5.17+ or a backport). (9)'s "below 6.2" is replaced: lockdown=confidentiality refuses probe reads on
every measured kernel, 6.17 included, so the rdonly build is the only one that loads under it (6.17, RHEL 9.8), and
a kernel without `bpf_rdonly_cast` in BTF (AL2023 6.1) has no plane mode under confidentiality. (3)'s probe checks
both kfuncs and picks the object build; the step-A plan generates both builds. The Why's "32-level walk with direct
loads loaded under confidentiality on 6.17 and 5.14" measured a walk with no probe read; the walk that crosses mounts
needs a reader, and under confidentiality that is `bpf_rdonly_cast`. (2)'s LTO exclusion stands: no measured row
(6.17, RHEL 9.8, AL2023 6.1) has Clang LTO, and fmod_ret loaded, attached and refused on all three. The slot's row
maps are ADR 0025's as amended the same day (kept per slot, rows carry gen). tier cgroup with a plane mode and tier
bpflsm share one `compile --test` column (ADR 0019's 2026-09-29 note).

*Amended 2026-09-29 (T2):* the walk's scalar pointers travel through the
task's own storage (`tego_plane_scratch`), not the per-CPU slot T0 used: an LSM or fmod_ret program runs with
migration disabled but can be preempted, so a per-CPU slot could be overwritten by the next program on the same
CPU and the walk would read another task's dentry. Task storage is private to the task that is deciding.

*Note 2026-09-29 (tier 2):* the same holds for the refusal sample's path buffer, which T9 had made
per CPU: filled in a `bpf_loop` before the ring reserve, it could be overwritten by another task's refused exec on
the same CPU and carry that task's path on this run's line. It is task storage now, created for the sample and
deleted after it; `bpf/tests` `TestPlaneKeepsNoPerCPUScratch` refuses a per-CPU map in any map `decide.bpf.c` uses.

*Note 2026-09-29 (tier 2 under lockdown=confidentiality; built):* (9)'s two readers now apply to tier 2's record too.
bpf/trace_proc.bpf.c is compiled twice (internal/bpf/gen.go): `trace`, CO-RE probe reads as before, and `tracerd`
(`TEGO_TRACE_RDONLY=1`), which calls no `bpf_probe_read_kernel*`: fields by direct loads off the programs' BTF
arguments, kernel strings a byte at a time through `bpf_rdonly_cast` (to `struct new_utsname`, whose first member is a
char array) in a `bpf_loop`, the connect's `sockaddr_in`/`_in6` through `bpf_core_cast`. Both are one object
(`bpf.ObjectTraceProc`: the same programs, maps and pins under one `bpf_hash`); `bpf.Load` hands out the build
`bpf.ChooseReader` picks by the plane's rule, `tracerd` wherever the kernel's BTF has `bpf_rdonly_cast` and `bpf_loop`,
lockdown or not, so one build per kernel and the one every run there loads. cgroup_track now reads by direct loads
(tp_btf, 5.5+) and cgroup_net already read through `bpf_rdonly_cast`, so each keeps one build. A second finding:
`bpf_probe_read_user` is not refused by lockdown, but cilium/ebpf v0.22.0 rewrote it (and the kernel reads) to the
legacy `bpf_probe_read` whenever its feature test for `bpf_probe_read_kernel` failed, which lockdown makes it do;
`internal/bpf` fixes that test to present (proberead.go; every supported kernel has the helper), so argv at exec and
`uprobe_ssl`'s capture load as written. Measured as root in the KVM guest on 6.17.0-41, booted
lockdown=confidentiality: `tracerd`'s 13 programs load in 123 ms; doctor's D7 29 of 29 hooks and capture's 6 of 6;
the internal/bpf, observe, enforce/cgroup, capture/uprobe and doctor suites pass. The same suites pass booted with
the host's lockdown (integrity), where `tracerd` is also the build loaded; there observe's
TestIntegrationChainReturnIsTheVerdict and TestIntegrationHeldRecordsAreTheirOwnActions (the earlier held-record
fixes) pass under both builds, and under confidentiality under `tracerd` (with this change). **Condition:** under lockdown=confidentiality a kernel without `bpf_rdonly_cast`
or `bpf_loop` in BTF (AL2023 6.1) has no tier-2 build: Prepare refuses naming lockdown before creating anything, and
D7 fails tier cgroup's trace_proc rows with that cause, so tier selection falls to landlock (not measured on that row).

*Note 2026-09-29 (T12):* step A (`file_open`, `bprm_check_security`, `path_rename`, `path_link`, `path_unlink`, `path_rmdir`) is built in both modes and runs at tier cgroup (T2 to T6, T8, T9, T10); the `bpflsm` constructor (T7), steps B to E (T13 to T16) and the kernel matrix suites (T11) are not. enforce-plane carries the per-rule state.

*Note 2026-09-29 (walk review, built):* (1)'s "a mount crossing counting as one" is replaced: a mount crossing
costs the walk no step. The crossing cost an extra step because the callback moved to the mountpoint and the next
iteration looked the mountpoint up before climbing, so a row 64 components above a file with one mount between them
was refused by the kernel and allowed by decide.PlaneRows.Find and compile --test (enforce-plane R25). The callback
now skips the lookup at a mountpoint it has just crossed to (the mountpoint names the path the mount root below it
did) and counts levels climbed, not iterations: the walk's step is Find's, path components only. bpf_loop runs
2 x (64 + 1) iterations (TEGO_PLANE_WALK_ITERS), a lookup and a crossing at each level; a climb that crosses more
mounts than that (mounts stacked on one mountpoint) runs out and is refused path-unresolved (bound), which Find does
not model. enforce-plane R7; internal/bpf TestPlaneStepAHooksDecide's deep and mount cells, bpf/tests
TestPlaneWalkFailsClosed.

*Note 2026-09-29 (T15, step D; built, enforce-plane §2.11):* step D attaches at `socket_connect` and
`socket_sendmsg`, restricted to AF_UNIX, instead of (5)'s `unix_stream_connect` and `unix_may_send`. Those two run
after the path lookup and see the peer socket; the contract's rows (`tego_unix_names`, shared with tier 2's
`connect_unix`) and the supervisor's `/proc/self/fd/<n>` relay are keyed by the name the caller passed, which the
socket hooks see in the kernel's own copy, before the lookup, as `connect_unix` does on 6.7+; and `unix_may_send`
runs for every datagram of a connected socket too. So below 6.7 a name gets exactly the verdict it gets on 6.7+. Two
departures from (6) and (11), both for parity with `connect_unix`: the run is looked up by the socket's cgroup, not
the caller's, since the supervisor connects the agent's socket from the launcher's cgroup (enforce-cgroup-observe
§5 R1); and the hooks write no refusal sample, since the unix connect's or datagram's one ledger line is the
supervisor's (enforce-cgroup-observe §5 R7). The two programs are loaded only where the build did not load
`connect_unix`, so no name is decided twice; E54's P1 `socket_sendmsg` for inet sockets is unchanged.

*Note 2026-09-30 (P7, enforce-plane §10.1):* measured with a raw open+close loop (200,000 opens, one pinned CPU, the modes alternated over nine rounds, best round), 6.17.0-41 in a KVM guest, `record: summary`, over tier landlock: +938 ns (cgroup, LSM), +833 ns (cgroup, fmod_ret), +791 ns (bpflsm) for the worst of three paths (no row, a write path, a path seven components deep); `record: off` +88 to +281 ns. The two modes are indistinguishable at this resolution, so (11)'s cost ordering is withdrawn: neither mode is cheaper per open.

*Amended 2026-10-05 (ADR 0041, proposed):* the Consequence's "R15c's deny_write ... close
race-free" holds where a plane loads, and no plane-less tier is left deciding `deny_write` on copied names: since
2026-10-03 a non-empty `deny_write` set refuses launch at tier landlock and at tier cgroup's listener fallback
(agent-contract R20, enforce-landlock R5a). The default at those tiers, and a recorded opt-out, are
[ADR 0041](0041-race-free-supervisor-decisions.md) D8 (open when this note was written; decided in the note below).

*Amended 2026-10-05 (ADR 0041 accepted, D1 decided (a)):* the note above holds only under `fs.assurance: kernel`. By
default tier landlock and tier cgroup's listener fallback decide `deny_write` again on copied names (R15c), best
effort and disclosed (one compile warning per target; run_start `best_effort` `deny_write/default`). The
Consequence's race-free closure holds where a plane loads, as before.

*Note 2026-10-05 (the hook set as built):* (5)'s P1 remainder is built except the inet hooks. `bpf.PlaneHooks` holds 28 hooks: after steps A to D, `socket_bind` (AF_UNIX addresses only) and `socket_listen` (AF_UNIX, and inet TCP against the cgroup bind table) decide a declared `net.listen`, `ptrace_access_check` (ATTACH) and `ptrace_traceme` keep a trace inside the run and gen, `bpf` refuses every command of a governed task, and `key_permission` (optional) refuses unless `keyring: true`. `socket_connect`, `socket_sendmsg` and `socket_bind` for inet families stay out: network stays on the per-run cgroup programs and the supervisor. enforce-plane §1, §2.1, §2.2, R3 and §2.20 carry it.

*Note 2026-10-05 (residual stated):* (15) gains one residual. No hook is on `inode_setattr` or `file_ioctl`, and Landlock has neither, so a `deny_write` target's timestamps and inode flags are not protected: an agent that owns the target can set its atime and mtime with `utimensat(2)`, and can set flags that need no `CAP_LINUX_IMMUTABLE` (`noatime`, `nodump`) with `FS_IOC_SETFLAGS` or `FS_IOC_FSSETXATTR`. B's attribute hooks keep its mode, owner, xattrs and ACLs protected, and the file-op hooks keep its contents and name protected; mtime-based integrity checks over it are not. enforce-plane §9 carries the line.

*Amended 2026-10-05 (ADR 0023's acceptance note, correction of fact):* "Prerequisites on master: … 0023" was not
met when tier 3 was built: ADR 0023 was proposed, not built, and the fill's safety rested on enforce-plane R16's
(mnt_id, ino) check alone. It becomes true in two halves: the Landlock set's held descriptors and the ruleset are
owners at ADR 0023 C5, and the fill leases them across the iterator at C11b.

*Note 2026-10-05:* the process controls named in the review note on the hook set as built
have governed-run cells, in both modes and at tier bpflsm (enforce-plane §2.20, R3). They state what a reading of (5)
would not: Landlock's ptrace scope
answers an attach from the run to a task outside its domain before the plane in lsm mode, where bpf is last in the LSM
list, so the plane's `ptrace_access_check` refuses there only a task in the run's own domain that is outside its cgroup,
and `ptrace_traceme` under an unconfined parent is the plane's alone; `key_permission` is the contract's `keyring: true`
and nothing finer, per permission check; and `bpf` and `key_permission` are behind the seccomp filter's arms in a
product run, so a cell reaches them only through the test build's `TEGO_TEST_FILTER_OMIT`. (5)'s decision text and
residuals are unchanged.

*Note 2026-10-06 (KT5, enforce-plane §10.1):* (14)'s exception for contracts with `fs.ask` entries is measured by kill test 5 (`test/e2e/kt5-ask.sh`, results in `test/vm/README.md`). On the 6.17 guest's two boots and on six matrix rows, an `fs.ask` and a `net.ask` entry the workload never touches turned the pip build's 19 notifications at tiers cgroup and bpflsm into 2,509 and its run 160 to 692 ms slower (60 to 280 µs for each notification kept); the 20-step agent, whose run notifies twice, was within 12 ms; every cell was inside the allowance, which is the larger of 1% of wall time and 1 s, by its 1 s. The exception stands; its cost is a stated condition, which a workload of about ten thousand fs notifications a run would exceed, and the narrower filter that removes it (a filter arm that keeps only the write-opens whose path can match an ask scope) is not built.

*Amended 2026-10-06 (arm64):* (15)'s arm64 residual says the plane is unmeasured there until an arm64 row runs ADR 0017. A measurement of the plane itself no longer waits for that row: `ci.yml`'s `build-test-arm64` runs, as root on GitHub's arm64 runner, the plane's hook sets (`TestPlaneLoadsAndAttaches`, `TestPlaneStepAHooksDecide`), a run decided by it in fmod_ret mode (`TestPlaneRunEndToEnd`), doctor as root and the stress cell for the recorder's directory walk (`TestPlaneSeqcountStress`, enforce-plane §2.15), and fails unless each passed, with a fmod_ret cell among them. The decision text stands: the probe decides there and the fallback is expected until a log says otherwise, and nothing has run there yet. ADR 0017's conformance on arm64 is a later step of the same job, and what the first log shows is entered in enforce-plane R28.

*Amended 2026-11-02 (16), fmod_ret mode needs a kernel that does not preempt kernel code:* (2)'s fmod_ret mode is
offered only on a kernel whose preemption model never preempts kernel code (none or voluntary); doctor rules it out
before any load under full, lazy and RT preemption, and wherever nothing proves which model the kernel runs.
In fmod_ret mode the plane's programs are BPF tracing programs, which the kernel's trampoline runs under a per-CPU
recursion check (`bpf_prog_check_recur`, `__bpf_prog_enter_recur`, unchanged in the 7.x sources): a program already
active on a CPU is skipped there, a recursion miss is counted, and the hooked `security_` call goes on as if the
program had returned 0. Where the kernel preempts kernel code, a task preempted inside a plane program keeps it
active on its CPU, so every other task that reaches the same hook there before it resumes is decided by nothing. LSM
programs take no such check (`bpf_prog_check_recur` is false for `BPF_PROG_TYPE_LSM`), so LSM mode is not affected.
Measured 2026-11-02, one tier-cgroup run opening a `deny_read` file in fmod_ret mode: on 6.17 booted `preempt=full`,
16 processes made 320,000 opens and 87,075 of them succeeded (`tego_fmr_file_open` counted 87,085 misses); under lazy
preemption (Fedora's 7.0 default, `Dynamic Preempt: lazy`, and 6.17 booted `preempt=lazy`) eight processes opening
it beside eight spawning `/usr/bin/true` opened it 2,809 and 2,313 times in 20 s, which no privilege and no
`io_uring` were needed for; under 6.17's default voluntary preemption no open succeeded in either workload and no
program counted a miss. The run ended with exit 0 and a verified chain each time: nothing recorded the bypass.
Kernels from 7.0 offer x86_64 and arm64 (which have lazy preemption) only full and lazy (`preempt=none` and
`voluntary` are refused), so on those architectures fmod_ret mode ends with 7.0: tier cgroup there needs `bpf` in
`lsm=` for a plane mode, else it decides on the fanotify listener, and doctor says which and why.
Doctor admits the mode on proof alone, and refuses it on any doubt (`internal/doctor` preempt.go; *revised
2026-11-03*, after a review found a build's default, a kernel log line and a boot line each standing in for a live
mode they do not prove: a dynamic kernel booted `preempt=full preempt=bogus` read as its voluntary default, and a
voluntary default read where debugfs was not mounted). A build that is not PREEMPT_DYNAMIC must have a readable config
(`/proc/config.gz`, `/boot/config-<release>`, `/lib/modules/<release>/config`) setting `CONFIG_PREEMPT_NONE` or
`CONFIG_PREEMPT_VOLUNTARY` and none of `CONFIG_PREEMPT`, `CONFIG_PREEMPT_LAZY`, `CONFIG_PREEMPT_RT` and
`CONFIG_PREEMPT_DYNAMIC`, with no PREEMPT flag in `uname -v`. A PREEMPT_DYNAMIC build (by `uname -v` or its config)
must have `/sys/kernel/debug/sched/preempt` readable now, selecting none or voluntary; the boot line, the build's
default and the kernel log are not read. Debugfs not mounted, or refused by lockdown, refuses the mode, with LSM mode
and mounting debugfs as the fixes. The reading is never kept: every probe reads it, and a reused answer is held to a
fresh reading before a run or an adoption takes fmod_ret mode from it: a pinned build's answer (`adoptStillAdmitted`),
a run-probe cache hit, which probes when the reading differs from the one the answer was kept under
(`planePreemptCurrent`, `TestACachedPlaneAnswerIsHeldToTheKernelsModeNow`), and `tego agents --follow --adopt`'s
prepared boundary backend, which is prepared and selected again (`preparedAdoption.fmodRetLapsed`,
`TestGuardSelectsAgainWhenFmodRetLapses`).
A test build's `TEGO_TEST_PLANE_PREEMPT=waive` (`internal/doctor` preempt_testhook.go) waives the precondition so that
CI's root suites keep exercising fmod_ret mode's decisions on GitHub's 7.0 runners, as they did before it; a product
build never reads it. A run under the waiver can meet the skip; there `TestPlaneSeqcountStress` measures the directory
walk and counts its wrong allows without holding them (no count of the kernel's skips can tell a skip-made wrong allow
from a plane fault), and every other plane test holds them to none, as before; the stress cell holds them to none
wherever the mode is admitted without the waiver.
What this amendment leaves open, stated rather than watched (docs/GAPS.md C53): root switching a dynamic kernel's
mode while a run or an adoption lives is not seen by it (root is outside the threat model; the next run or adoption
reads the mode again); recursion misses are not detected at run time; and the tier-2 recorder's fexit programs
(ADR 0016) are tracing programs too, skipped the same way in both modes on a kernel that preempts kernel code, so they
can drop records with no `tego_lost` count. Detection, with an adoption frozen rather than released when it fires, is
a follow-up.
(15)'s arm64 residual: GitHub's arm64 runner's 7.0 kernel is built `SMP PREEMPT`, so fmod_ret mode is ruled out there
and `build-test-arm64` checks doctor's refusal; of the 2026-10-06 amendment's plane run, the directory walk's stress
cell still runs there in fmod_ret mode under the waiver, required, and the end-to-end and rename cells no longer do.

### CI portability amendment (2026-11-04): built-in walk verifier form

ADR 0113's protected-name ancestry check now follows the global-subprogram plus
`bpf_loop` callback form of the filesystem walk. Its dentry is passed as a scalar
through the task's existing scratch field; its result packs the matched rule and
match class without a trusted-pointer argument. The 64-level bound and protected
name/peer semantics remain. The verifier's existing instruction budgets remain,
including socket_listen's separately measured budget. The native Unix peer's
inode and link count use the selected probe/readonly reader throughout, rather
than dereferencing an address returned by `bpf_probe_read_kernel`.

The `capable` hook recognizes only a kernel-installed credential override for
backing filesystem work (ADR 0055's CI portability amendment), never an io_uring
personality: an io thread or a task with an io_uring context keeps the floor. The
task's own CAP_SYS_ADMIN refusal remains mandatory, including in fresh user
namespaces.

A native terminal bind result with no kernel permission marker stays `observed`,
`unmatched`, with the actual syscall return, unknown authority and an unavailable
name, and now explicitly counts `bind-metadata-missing`. A copied supervisor
attempt cannot replace that missing evidence. ADR 0113's early, frozen pathname
lookup errors are instead supervisor-owned completions: ownership is saved
before the errno is returned, the supervisor records the result and the terminal
producer's duplicate is suppressed. The lookup-failure regression requires one
such correctly owned line in every mode, with no metadata-gap or waiver
exception. This does not change fmod_ret's preemption admission rule.

### RHEL 9 syscall outcome context correction (2026-11-05)

`tego_bind_result` is a `BPF_PROG_TYPE_TRACEPOINT` program attached through
`link.Tracepoint` / `BPF_LINK_CREATE(BPF_PERF_EVENT)` to
`syscalls:sys_exit_bind`. It and `tego_listen_result` emit actual terminal results
and clear the per-task listener marker, including failed operations. They remain
mandatory for an explicit listener policy. They were added in a498c3bf6
(2026-10-04), before the product rename in 2836e5bb1
(2026-10-24). Public v0.1.0 (commit 309cead) includes them with the faulty context.

The fault is CO-RE against `trace_event_raw_sys_exit`, which describes
`raw_syscalls:sys_exit`, rather than the individual syscall event. In the exact
matrix kernel, AlmaLinux/RHEL 9's 5.14.0-687.65.1.el9_8.x86_64, the backported
`trace_entry.preempt_lazy_count` makes the common header 12 bytes. BTF places the
raw event's `long id` at 16 and `ret` at 24. The individual event's `int nr` is
at 12 and `ret` at 16; its size is 24. A CO-RE load at 24 therefore exceeds the
event's extent. `perf_event_set_bpf_prog` rejects that access with `EACCES`,
rendered by cilium/ebpf as `cannot create bpf perf link: permission denied`.
This is neither missing perf-link support nor a lockdown refusal: in the same
integrity-locked guest, a minimal tracepoint program reading offset 16 attaches
and one reading offset 24 fails. The unmodified network-control suite reproduces
the latter error. Tracefs's format and both BTF types agree on the distinction.
The kernel producers and bound check are in
[`trace_syscalls.c`](https://github.com/torvalds/linux/blob/v6.12/kernel/trace/trace_syscalls.c)
(`perf_call_bpf_exit`) and
[`events/core.c`](https://github.com/torvalds/linux/blob/v6.12/kernel/events/core.c)
(`perf_event_set_bpf_prog`).

Use `syscall_trace_exit` for bind, listen, execve and execveat outcomes, retaining
CO-RE against the individual trace record layout. The two exec hooks had the same
bug but took the optional, disclosed fallback instead of failing preparation.
On supported layouts no hook is skipped by this correction and no enforcement
or recording property is traded away.
Existing missing-hook refusals and optional exec fallback disclosures remain.

Review follow-up: the trace record is not the `syscall_tp_t` BPF wrapper supplied
by `perf_call_bpf_exit`. All supported wrappers supply an eight-byte return at
16, but an enlarged trace record could relocate the CO-RE read to 24 while its
32-byte extent still passes the perf attachment bound check. Before loading or
adopting any selected syscall-result program, the runtime now reads that event's
tracefs `format` and requires `ret` at offset 16, size 8. Doctor applies the same
check before loading either the real hook or a stand-in. A divergent, missing,
malformed or unreadable return layout is a hard refusal with the event and plain
reason, including for present optional exec events; it cannot become the optional
attachment fallback. Doctor and the run's tier derivation withhold root tiers
when any of these hooks fails the layout check, including listener rows that
otherwise only describe optional network capabilities. The runtime checks only
selected hooks, so an unselected listener imposes no format dependency there;
truly absent optional exec events retain their existing disclosed fallback.
`TestSyscallResultContextRejectsUnsupportedLayouts` covers divergence and missing
returns for all four programs. Doctor's
`TestSyscallResultContextRefusalWithholdsTierBeforeLoad` proves no object or
stand-in loads and tier rejection keeps the reason; the runtime's
`TestSyscallResultContextRefusalPrecedesLoadAndAdoption` proves both spec paths
refuse before a collection can be loaded or pins adopted. This narrows admission
on unverified layouts without removing an enforced property on supported ones.
The regression relocates the actual compiled return loads against synthetic
8-byte and RHEL 12-byte headers in both probe and readonly objects: the previous
objects fail all eight RHEL cases by reading offset 24, and the corrected ones
read offset 16 throughout.

The historical support claim needs narrowing: v0.1.0's root-tier contracts with
`net.listen` failed before the agent started on this RHEL layout. Ordinary
outbound-only contracts did not require the listener hooks. Neither the kernel
minimum nor a no-op doctor attachment probe established the full listener path.
TIERS, CAPABILITIES and GAPS now carry that distinction.

The requested `TestPlaneExecProcDirOracle` also had a separate RHEL fixture
failure, present in the original matrix log: this kernel permits the caller to
list `/proc/1/fdinfo`. It lacks the directory's newer `proc_fdinfo_permission`
check, so the test's inaccessible-directory premise does not hold. The test now
probes the listing directly as the caller before choosing its fixture. When
fdinfo is public it uses root's `/proc/1/fd`, retaining all three EACCES results
and the no-`exec_missing` assertion in every mode and contract. This is DAC
coverage on RHEL; the fdinfo permission-hook oracle remains covered on kernels
that deny that listing. The test logs this distinction without skipping. This
changes no product policy and adds no authority beyond the kernel's own.

KVM validation (2026-11-05): all ten affected network, listener, exec-outcome
and proc-directory suites passed in every cell below, with no suite or subtest
skipped. The compiled-context relocation regression also runs without root.

| Matrix kernel | `lsm-bpf` boot | `default-lsm` boot |
|---|---|---|
| `rhel-9`, `5.14.0-687.65.1.el9_8.x86_64` | 10/10 | 10/10 |
| `fedora-7.0`, `7.0.14-201.fc44.x86_64` | 10/10 | 10/10 |

The guests used the matrix's `lockdown=none` setting, one guest at a time, with
3 GiB each. Fedora's fmod_ret cases use the matrix's explicit test preemption
waiver; this is a compatibility regression check, not product preemption-safety
proof. The RHEL fixture's DAC limitation above remains. Other matrix failures,
other kernel updates and live distro LSM policy are outside this proof.

### Verifier budget amendment (2026-11-10): one kernel family charges the plane more

The plane's root tests hold each program's verified-instruction count to 20,000, the figure set against T0's form d
(391-896 per program on 5.14, 6.1 and 6.17). On Fedora 44's 6.19.10 every walk-calling program exceeded it, up to
63,939 (rd) and 28,681 (pr), with the same object bytes whose largest program verified in 13,819 on 5.14 and 6.12,
14,562 on 6.18 and 6.19.3, and 19,834 on Fedora's 7.0.14. Measured in guests with one test binary: mainline 6.19.3
verifies rd file_open in 11,367 and mainline 6.19.4 in 59,827, the Fedora figure exactly, as do 6.19.10 and
6.19.14. The one bpf_loop-specific verifier change between 6.19.3 and 6.19.4 is the stable backport de2f14d97bda of
f597664454bd ("bpf: bpf_scc_visit instance and backedges accumulation for bpf_loop()"), which makes the verifier
treat every bpf_loop callback as a loop for state accumulation. T0's spike shows the same split: its bpf_loop forms
grew (d-rd 1,032 to 3,789, d-pr 655 to 1,919, c-rd 1,975 to 7,507) and its plain-loop forms did not move (a-rd
248,374 and b-pr 67,514 on both). The commit was not isolated by building a kernel without it; 6.19.4 also carries
65d114b5270b (sync_linked_regs id preservation), which does not touch bpf_loop and would not leave the plain-loop
forms unchanged. Fedora's 7.0.14 and 7.2.9 carry f597664454bd and verify the plane in 15,741 and 14,918 (rd
file_open), so 7.0 offsets it by some change not identified here. The real plane loads on 6.19.10: root `tego
doctor` reports tier bpflsm with every hook loaded, and the kernel's own limit is 1,000,000.

The budget is now per kernel family (`internal/bpf/plane_budget_integration_test.go` `planeCharges`): 20,000
everywhere except Linux 6.19.4 to 6.19.y, where it is scaled by what that family charges the same bytes against
6.19.3, per reader: 87,817 (rd, 63,939 / 14,562) and 49,527 (pr, 28,681 / 11,582), the headroom 6.19.3 has. T0's
plain-loop walks alone cost 248,374 (a-rd), 289,281 (b-rd) and 67,514 (b-pr) there, over those budgets. Form a-pr
(16,338 there) is cheaper than the larger pr programs on that family, so no budget there tells it apart; it still
fails on the other kernels. The family is a release range because the change came by stable backport, which no BTF
type marks; a distribution kernel elsewhere that took it without 7.0's offset fails with its counts logged.

Rejected: scaling by T0's form d walk measured on the running kernel. It tracks this family (d-rd 3,789) but not the
plane elsewhere: RHEL 9.8's 5.14.0-687.61.1 verifies d-rd in 2,975 and Fedora's 7.0.14 in 2,179, while the plane
there costs what it costs on 6.12, so the rd budget would have loosened to 70,331 and 51,514 on those kernels
(7.0 is the hosted runners' kernel), and on RHEL 9.8 a plane program whose walk became form a-rd (35,855 alone on
5.14 in T0) would have passed. socket_listen keeps its own 64,000, which 6.19.4 did not move.
