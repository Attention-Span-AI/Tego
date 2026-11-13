# ADR 0025: the plane keys fs rules by the kernel inode pointer, filled in the kernel into a per-run map and held alive by the run's own Landlock domain

Status: accepted 2026-09-29, as amended by T0's measurement ((1): a slot keeps its row maps and rows carry gen; see the 2026-09-29 notes below); built with step A (TIER3-PLAN §10, T4-T6 done 2026-09-29). Proposed 2026-09-23. Lands with ADR 0024 step A as one unit. Supersedes ADR 0010's BPF_MAP_TYPE_INODE_STORAGE (its O_PATH descriptors stay). Amends ARCHITECTURE §10 and SEMANTICS §2 'Identity'.

Decision: (1) Plane rows live in a per-run inner hash (BPF_F_NO_PREALLOC), held in an outer map indexed by run_idx like ADR 0026's rings. Rows are keyed by struct inode *, with the value {kind, rule_idx, gen, i_ino, i_generation, s_dev}, where gen is the run's tego_run.gen (ADR 0026's 2026-09-25 amendment). Exec rows also bind the parent directory's inode and the final name's bytes, so a hard link under another name or in another directory is refused, as SEMANTICS §4 requires, and nothing depends on a dentry's lifetime. Watch entries have no row; ADR 0016 attributes them from the resolved path. A slot keeps its rows inner map and its exec-rows map across runs, as it keeps its rings (ADR 0026 (6) as amended): the outer is updated only when a slot is first used, because every outer update waits an RCU grace period. A row whose gen is not the run's counts as absent and the walk goes on past it; this is exact because all of a run's rows exist before its run_set row is armed. A slot's previous rows are cleared in the kernel, off the run's path, by a BPF_PROG_TYPE_SYSCALL program run through BPF_PROG_TEST_RUN that looks the slot up in the outer and deletes every row with bpf_for_each_map_elem, at the run's end or at the next Prepare before its fill, whichever holds the slot. Userspace never reads a key, so it never handles a kernel address. (2) Rows are filled in the kernel by an iter/task_file program over the launcher's own held O_PATH descriptors (each owned by a sys.FD, ADR 0023). A map gives the wanted descriptor numbers and their row templates. The program keeps only the launcher's tgid, using task-scoped iteration where the kernel has it (bpf_iter_link_info.task, 6.1+, probed) and otherwise iterating every task with a tgid filter. For each descriptor it reports (mnt_id, i_ino). Prepare compares these with /proc/self/fdinfo/<n>'s mnt_id and ino, which fs/proc/fd.c prints from the same kernel fields, and fails Prepare on a mismatch. st_dev is never compared with s_dev: btrfs reports the subvolume's anonymous device, and overlayfs reports a layer's. (3) Rows are held valid by the run's Landlock domain. For every inode the plane keys (entry inodes and exec rows' parent directories), the tier-2/3 Landlock plan (ADR 0028) adds a rule whose rights are a non-empty subset of what the domain already grants there. That rule grants nothing new, and Landlock's reference keeps the inode alive while any process carrying the domain exists, which is every process a row can apply to. An entry inode with no such subset needs no row, because Landlock alone refuses everything there. A parent-directory binding that cannot be pinned this way is verified on every hit and refuses on a mismatch. (4) On every hit of a row of the run's gen, the program compares i_ino, i_generation and s_dev with the row; gen and this check together catch a recycled inode pointer. A mismatch refuses with path-unresolved and bumps a counter the recorder turns into a gap; it is a fail-closed assertion that cannot fire by construction. (5) Stated residual, with its true polarity: an unmount of a ruled filesystem loses the plane's rows for it, which fails open for deny rows under a grant from above the mount, while Landlock, losing its rules, refuses more. This cannot happen while the launcher lives, because its O_PATH descriptors keep the mount busy and the superblock alive. After the launcher's death it is bounded by the reaper, which ends the orphan within milliseconds (ADR 0020), and, if the reaper is dead too, by the next sweep.

Why: [documented, ADR 0010 and GAPS B6] Inode storage works only where bpf is an active LSM; creating it while BPF LSM is inactive corrupts inode->i_security on kernels before the 2026-06-30 guard, 6.17 included. fmod_ret mode runs exactly where bpf is inactive.
[documented, ADR 0010] stat pairs are not identities on btrfs or overlayfs. [documented, fs/btrfs/inode.c] stat reports root->anon_dev on btrfs.
[documented, security/landlock/fs.c] get_inode_object takes ihold for each rule's inode; release_inode drops it only when no ruleset or domain references the object.
[documented, fs/proc/fd.c at v5.14, v6.1 and v6.6, checked today] fdinfo prints real_mount(f_path.mnt)->mnt_id and file_inode(file)->i_ino.
[documented, include/uapi/linux/bpf.h v6.0 vs v6.1, checked today] Task-scoped iteration (task.pid_fd) appears in 6.1.
[measured] Walks with direct loads and one lookup per level load on 5.14 and 6.17, under confidentiality too.
[inference] One host-wide rows hash keyed {run_idx, inode*} lets an interrupted purge leave a previous run's write rows under a reused slot (fail-open), and deleting rows would make userspace iterate kernel addresses. [inference] Unscoped iteration walks every task's descriptor table at each Prepare; tens of ms on a busy server.

Security argument: Rows cannot outlive their inodes while any process they apply to exists. Every member of the run's cgroups descends from the child stage and carries its domain, and the domain holds the inodes. Rows outliving every member are unreachable: cgroup_rmdir removes run_set rows, and cgroup ids are not reused within a boot. No run inherits another's rows: a row applies only when its gen is the reading run's gen, and a slot's rows apply only while the slot's header (enforce-plane R6) carries that gen. The gen is the slot's epoch, one more than the slot's previous run's, never 0, kept in the slot table across release, so it repeats only after 2^31 - 1 runs of that one slot, and every Prepare clears the slot's rows and rewrites its header before its fill anyway. (Before 2026-09-30 it was the low half of the run's own cgroup id, which this argument claimed the kernel never hands out twice in a boot. That was wrong: the low half is an ino from kernfs's cyclic idr over [1, INT_MAX], shared with every kernfs node, and repeats once the idr wraps.) A run's rows are all written before its header, and its header before its run_set row exists. A clear zeroes the header first, so a clear that is interrupted leaves a slot that refuses every decided hook of a run still naming it, and rows of another gen, which are absent to every later run. The neutral rule is checked, not assumed: the plan's union at every path is proven unchanged. Stated residuals: item 5's unmount case; root outside the run can read inode addresses (heap, not text) from the map; rootless adopted containers carry no fs domain, so their rows need another holder (the launcher's descriptors plus the reaper), which is a condition of P2.

Options considered: Chosen: inode-pointer keys in per-run inner maps, filled in the kernel, pinned by the domain, verified on fill against fdinfo and on every hit.
Rejected:
- ADR 0010's inode storage: LSM mode only, and B6's corruption hazard.
- (superblock, inode number) keys: btrfs subvolumes share a superblock and repeat inode numbers, so an allow row can collide nearer than a deny row.
- Pointers pinned by the launcher's descriptors alone: fail-closed only while the launcher lives.
- Pointers computed in userspace: hands kernel addresses to userspace with nothing tying address to object.
- One host-wide rows hash keyed {run_idx, inode*}: leaks rows across slot reuse and makes userspace read keys.
- Comparing s_dev with st_dev: fails on every btrfs host; fdinfo's mnt_id and ino replace it.

Consequence: B6 leaves the design: no inode-storage map is ever created, and doctor's LSM check matters only for choosing LSM mode. Each declared entry still holds one O_PATH descriptor for the run. The tier-2/3 Landlock ruleset gains one neutral rule per keyed inode. Prepare gains the fill, whose unscoped fallback cost is measured and stated.

Implementation plan:

- bpf/decide_fill.bpf.c: iter/task_file with the tgid filter and the wanted-number map. mnt_id is read the way the walk reads a mount (ADR 0024 (9)): bpf_rdonly_cast where BTF has it, else a CO-RE probe read, so under lockdown=confidentiality the fill needs the rdonly build too.
- The core (ADR 0028): NeutralRule in the plan, with a unit test that the plan's union at every path is unchanged.
- enforce/cgroup plane rows: a per-slot inner map created on the slot's first use and kept; fill with the run's gen; fdinfo verification; the in-kernel clear at Detach, in purgeSlot, in the reaper's sweep and before the next fill of the slot. The maps of slots above a build's ring pool are removed off the run's path with its rings (ADR 0026's 2026-09-25 amendment).
- Sizing: a cap on keyed inodes per run, reported by compile. The outer map's idle memlock is stated with ADR 0024's figures.
- Measure the fill on RHEL 9 5.14 (with or without task-scoped iteration) in a guest with 2,000 processes and 200k descriptors, and state or bound it.
Tests as root in GUEST and on MATRIX:
- The launcher closes its descriptors and is SIGKILLed with the reaper held, and caches are dropped (echo 2 > /proc/sys/vm/drop_caches): the orphan still has a deny_read beneath a write entry refused.
- A synthetic mismatching row refuses and counts.
- A descriptor number reused on another file fails Prepare.
- An interrupted clear (the previous run's rows left in the slot) is walked past: the next run in the slot is neither refused nor granted by them.
- Conformance cells on btrfs subvolumes (a loop-file btrfs in the guest) and on overlayfs.
- A hard link under another name is refused; the same name is allowed.
Docs: ADR 0025; ADR 0010 superseded; ARCHITECTURE §10; SEMANTICS §2 'Identity'; GAPS B6 (leaves the design).

*T0 spike, 2026-09-29 (measured; the row map per run, TIER3-PLAN §3 "Per-run cost trap"):* `tools/spike/walk
rowmap` in the KVM guest (2 vCPU, 2G) with an fmod_ret/security_file_open program that references the outer
attached, 20 runs each, 64 rows a run, raw output in `tools/spike/walk/results-2026-09-29.tsv`. Per run, as (1)
has it (create the inner HASH, NO_PREALLOC; insert it into the HASH_OF_MAPS outer; delete it from the outer and
close it), median (min-max) in ms:

| Row | create | outer insert | outer delete | per run |
|---|---|---|---|---|
| 6.17.0-41 (quiet host) | 0.14 | 9.62 | 6.90 | 19.7 (9.7-34.8) |
| RHEL 9 5.14.0-687 | 0.15 | 5.87 | 5.75 | 11.8 (8.8-17.8) |
| AL2023 6.1.186 (HZ=100) | 0.19 | 39.8 | 39.8 | 79.8 (69.8-99.7) |

The outer insert and delete each wait an RCU grace period (ADR 0026's 2026-09-25 amendment), and a 100 Hz kernel's
grace period is 40 ms. Against it, a slot that keeps its inner map: the run's only on-path step is its run-set row
with a new gen, 0.00 ms (at most 0.04); stale rows count as absent (the spike's walk passed a row of the previous
gen on every row and form); the clear is a BPF_PROG_TYPE_SYSCALL program run by BPF_PROG_TEST_RUN that looks the
slot up in the outer and deletes every row with `bpf_for_each_map_elem`, 52 instructions, loaded on all three
kernels, 0.05-0.06 ms for 64 rows, off the run's path, and no key ever reaches userspace. Filling 64 rows costs the
same either way (0.16-0.28 ms). **Decided (for T1's amendment of (1) and (6)):** a slot keeps its rows inner map
(and the exec-rows map) like its rings; every row carries `gen` (the run's `tego_run.gen`); a row of another gen
counts as absent and the walk goes on past it, which is exact because a run's rows all exist before its run-set row
is armed; the slot's previous rows are cleared in the kernel off the run's path (by the run's end or the next
Prepare before filling, whichever holds the slot); gen plus the identity check catch a recycled inode pointer. ADR
0026 (6)'s "no plane-row inner map carries the slot" becomes "the slot's rows carry another gen or are cleared".
Kill test 4 go's margin keeps 12-80 ms a run it would otherwise lose.

*Amended 2026-09-29 (T1, TIER3-PLAN §11; accepted):* T0's decision above is folded into (1), (4), the security
argument and the plan, which described a new inner map per run: "purging a run deletes its outer slot, which drops
the whole inner map at once" is replaced by slot-kept row maps whose rows carry gen, a stale row counting as absent,
and an in-kernel clear off the run's path. Measured cost per run (the note above): 0.00 ms on the run's path against
11.8-79.8 ms for a new inner map per run. The security argument's "the slot is not reused while the inner map
exists" is replaced by gen, which is exact because a run's rows precede its run_set row. ADR 0026 (6)'s
reuse condition changes with it (ADR 0026's 2026-09-29 note). The fill's mount read follows ADR 0024 (9) as amended
the same day.

*Amended 2026-09-29 (T2):* exec rows are keyed by the executable's inode
pointer, with `{parent inode*, name}` in the value, not keyed by `{parent, name}`: one lookup per
`bprm_check_security`, and no key built from a name, which `lockdown=confidentiality` would block (probe reads
refused, T0). The name comparison without a string read (e.g. `d_name.hash_len` plus length) is T3/T4's; a
hard link under another name still fails it, as R16b requires.

*Note 2026-09-29 (T5):* (3)'s neutral rules are computed by the core (`decide.CompilePlane`, `PlaneRows.Neutral`): one
per keyed inode where the domain already grants a read right, carrying READ_FILE and READ_DIR only, so a neutral rule
never holds a write right even on another name of a keyed file. The union-unchanged property is checked over every
generated table (`TestNeutralRulesKeepTheUnion`); the builder applies the rules at T6. The keyed-inode cap is the slot
maps' sizes (4096 fs rows, 1024 exec rows), a compile error at bpflsm (docs/p0/enforce-plane.md §2.4).

*Note 2026-09-29 (T3, built; docs/p0/enforce-plane.md §2.5):* the name is compared by its length and every byte,
read as eight-byte words through the build's reader (`bpf_rdonly_cast` or a probe read), never by `d_name.hash`: the
kernel salts that hash with the parent dentry's address, which the domain does not pin (it pins the inode), so a
reclaimed and re-looked-up directory dentry would hash every name anew and refuse allowed execs. Two more key forms
share the exec-rows map, neither able to meet an inode pointer: a name key (FNV-1a of the name, top bit clear) for an
entry matched by its final component anywhere, and key 0 for the slot's policy row (an `exec:` section exists;
`exec.anonymous`).

*Note 2026-09-29 (T12):* built: the slot-kept row maps with `gen`, the in-kernel fill and clear (T4) and the neutral rules in the Landlock plan (T5, T6), run at tier cgroup and held by `TestPlaneRunEndToEnd`; `bpflsm` (T7) and the btrfs and mounted-root cells (T11, T13) are not.

*Note 2026-09-30 (exec rows per hard link: multi-call binaries, enforce-plane §6
E15):* found on Ubuntu 25.10, whose coreutils is uutils' multi-call binary: `/usr/bin/ls`, `cat`, `mkdir`,
`dirname` and a hundred more are symlinks to `/usr/lib/cargo/bin/coreutils/<name>`, 114 hard links of one inode that
pick the command from the name they were run under (busybox's applets have the same shape). (1) keyed an exec row by
the inode pointer alone, with `{parent, name}` in the value, so a contract listing two such commands had two rows
under one key: the fill refused the second (T5's condition 4) and Prepare failed at both plane tiers, kill test 4's
own pip contract included (enforce-plane §2.13's condition 3). **It was not a bypass:** bprm_check compared the row's
directory and name bytes with `bprm->file`'s dentry already, so an unlisted link of a listed inode matched no row and
was refused (`TestPlaneStepAHooksDecide`'s hard-link cell), and the supervisor, which still decides exec below the
hand-over, refuses it too (it matches the inode *and* the resolved path, since `exec.allow: [/usr/bin/sleep]` once ran
`/usr/bin/ls` through an inode-only match at tier 1). The defect was availability. What a one-row-per-inode map *could*
not do is admit two links under two entries; had the fill kept the last row instead of refusing, the first link would
have been refused, never an unlisted one admitted.

Decided: **an exec row is keyed by the link.** The key is `tego_exec_link_key(inode *, directory inode *, name key)`
(murmur3's 64-bit finalizer at each step, a bijection, top bit set, so never a name key nor the policy key 0), one
function in `bpf/include/plane_name.h` for the fill that writes a row and for `bprm_check` that looks one up, with the
name pass (the key and the byte compare) moved there from `decide.bpf.c` unchanged. The row carries the inode pointer
beside the directory's; a hit is a match only when the row's inode, directory and name bytes are the exec'd file's, so
no key is trusted alone and a collision can neither admit a file nor stand one link in for another, and a collision
among one run's rows is a duplicate at the fill, which fails Prepare. A recycled inode pointer under the same
directory and name still meets its row and refuses on the identity compare, as (4) says. The fill reads the name key
and the bytes from the dentry of the descriptor it keys and compares them with the entry's name byte for byte (the
length alone before), so each exec row needs a descriptor held at its own link: the Landlock plan's E7 dedupe holds
every name of one inode under the first that reached it, so an exec row whose descriptor was opened at another path,
and does not name this one now (`/proc/self/fd`), gets one of its own, identity only (no rule: Landlock's is on the
inode), opened without following its resolved path, and Prepare fails when it is not the inode held for the entry.
Fail closed where the link cannot be identified: a file whose dentry has no parent inode matches no row, a dentry
whose name is not the entry's fails the fill, and a path replaced while Prepare held it fails Prepare.

Symlink chains and interpreters: a row's path is the entry's resolved spelling (`decide.CompilePlane`'s `execPath`),
the link a chain ends at and the dentry `bprm->file` carries, so `/usr/bin/ls` is decided as
`/usr/lib/cargo/bin/coreutils/ls`, whose `d_name` is `ls`; an intermediate symlink is not a link of the file and needs
no row. A `#!` stage passes as before and its interpreter is decided by its own link. The ledger names the link: a
listed link's exec line carries its own entry (`exec[<entry>]`), a refused one the spelling `bprm->filename` passed
(the plane's sample) and the resolved link (the supervisor's line). Tier 1 and `compile --test` (the root model and
`decide.PlaneEvaluator`) decide on the resolved path, which names the link already, and change nothing; ADR 0017's
exec fixture gains two listed links of one inode, allowed under their own entries, and a third refused
(`exec-multicall-*`), in the column the plane shares. Cost: one mix of three words and no extra map lookup per
`bprm_check`; one descriptor per listed link beyond an inode's first; the row grows by 8 bytes to 312.

Stated residual, not closed here: a multi-call binary picks its command from `argv[0]`, which no exec rule sees. The
uutils build checked refuses an `argv[0]` that is not the name it was run under ("Security violation: Requested
utility `rm` does not match executable name", checked 2026-09-30); busybox honours any, so `exec.allow` naming one
busybox applet runs every applet, at every tier (SEMANTICS §4 as amended).

Measured 2026-09-30, fail first: before the change, `TestPlaneRunMulticallLinks` failed Prepare in all three cells
("two exec entries ... name one inode"), `TestPlaneFillKeysEachHardLinkOfOneInode` failed on the duplicate, and
`TestPlaneStepAHooksDecide`'s second-link cell refused the first link (its row overwritten by the second's). After:
all pass in the 6.17 guest's lsm boot and its kernel-LSM boot (fmod_ret), on AL2023's 6.1 and on RHEL 9's 5.14, and
ADR 0017's `exec-multicall-*` cells agree at tier landlock, cgroup and both plane columns on each. `bprm_check`
verifies at 4002 instructions in the pr build (3851 before) and 5611 in the rd build on 6.17. Kill test 4 at tier
`bpflsm` with its own contract (`dirname` and `mkdir`, two links of uutils' inode; no workaround) on the `debian-13`
row (6.12, `VM_ONLY=kt4 VM_KT4_TOOLS=1 VM_KT4_TIERS=bpflsm`): pip PASS 19/20 (baseline median 3116 ms, 3793 ms
under tego), npm PASS 19/20 (742 / 1199 ms); go FAIL 0/20 on time alone (206 / 716 ms against a 412 ms budget),
enforce-plane §2.13's and test/vm/README's standing condition on go at the plane tiers, with no refusal and no
Prepare failure.

*Note 2026-09-30 (the slot header; P1 slot fail-closed, enforce-plane R6):* a missing row read as a permission in
two places. `bprm_check` and step C took "no policy row of the run's gen at exec-rows key 0" for "the contract has no
`exec:` section" and passed, and `socket_create` took no net policy row for no `net:` section, so a slot whose rows
were cleared or never finished filling under a live run-set row let every exec, and every socket family, through.
Decided: a per-slot header, an ARRAY by `run_idx` of `{gen, flags, fs_rows, exec_rows}` (`tego_plane_slots`), whose
flags say what the policy rows said (exec decided, `exec.anonymous`, unix names below 6.7, `net:`, an ICMP entry).
Prepare writes it last, after the fill and its check and before Arm; every clear zeroes it before it deletes a row;
every decided hook reads it after its run-set hit, before its first decision, and refuses, counting `norows`, on a header of another gen. The
policy rows are gone. The gen is the slot's epoch (above), and Detach leaves a slot's rows and header in place when
a run-set row naming the slot could not be removed: that row's tasks are then decided by their own run's rows, not
refused everything, and the slot stays allocated until the reaper takes both. The task's scratch value became best
effort in the same change: the walk and the exec link key take the hook's pointers through the caller's stack, which
a global function reads as scalars, so no decision waits on a task-storage allocation; a lost record is counted
(`scratch`).

*Note 2026-10-05 (the btrfs cell, gates-1):* the loop-file btrfs acceptance above is `TestPlaneRunBtrfsSubvolumeInodeIdentity`
(internal/runtime/enforce/cgroup). It needed btrfs-progs, which no root gate provided, and test/vm/root-skips.txt allowed
its skip, so the (superblock, inode number) collision this ADR rejects had no gate behind it. It now mounts an embedded
empty btrfs with only the kernel's btrfs, which root-suites.sh's guests load by default; its skip is allowed in the plain
build only, so a skip fails every root run of the tegobpf suite, which holds the two subvolume roots (equal `i_ino` and
`s_dev`) to distinct pointer keys.

*Amended 2026-10-05 (ADR 0023's acceptance note, correction of fact):* (2)'s held descriptors "each owned by a
sys.FD" are not yet: they are the Landlock set's bare O_PATH numbers, which R16's check verifies after the fact. It
becomes true at ADR 0023 C11b, when the fill takes one lease per planned descriptor before the iterator runs, so a
close of the set in that window is deferred rather than landed; R16's check stays, as A5's re-verification.

*Amended 2026-11-11, corrected 2026-11-12 (mount aliases and the listener's release limit):* the plane's walk
holds a compiled path entry under a whole-tree alias on the same filesystem instance, including a bind of its
parent or whole filesystem, because the climb meets the entry's own dentry. A part of the tree mounted outside
it has no such climb. The file-bind conformance cell `mounts-bindfile/read-bind-alias-file` demonstrated the
missing refusal on Debian 13's 6.12.107 at cgroup@fmod_ret, cgroup@lsm and bpflsm before the holdability check
was added. That is saved guest evidence for the original defect, not evidence for fix round 2's changed
startup expectations.

Decision: `agent.MountTable.DetachedParts` of every read-deny row is part of the plane's holdability check
before loading (`ErrPlaneDetachedPart`, enforce-plane §6 case 16). Tier bpflsm refuses such a table
(`ErrPlaneCannotHold`, exit 125). Tier cgroup falls back to the listener, which now refuses other mount-table
spellings on the same filesystem instance of a compiled denied path tree or part of it
(`ErrListenerAlias`, ADR 0011). The run therefore never starts on that fallback. Auto selection cannot make a
detached part safe by selecting cgroup. Whole-tree aliases on the same filesystem instance retain the plane's
existing handling when the selected plane holds the rest of the contract.

Each `Prepare` shares one prepared mount-facts object with mounted-root composition, plane holdability,
listener policy and marks, and recorder initialization. Ordinary starts and record-only or boundary adoption
pass that object to the recorder before it starts; neither recorder reacquires the snapshot. Acquisition validates whole
mountinfo records and their graph, is bounded, and requires equal reads (`agent.ReadMountSnapshot`). Lookup
follows mount ancestry and is checked against statx mount ids. An unreadable, malformed, changing or
unverifiable table refuses a run whose rules need those facts. The ordinary listener hands the recorder only
its actual marked devices; detected aliases on the same filesystem instance need no decision handoff because
the listener refuses to start with them. Unit tests cover these preparation boundaries, including
`TestPrepareSharesOneMountSnapshot`, `TestRecorderUsesPreparedMountFacts` and
`TestAdoptionSharesPreparedMountSnapshot`. The updated kernel expectations are owed in a guest on Debian 13's
6.12 and Fedora's 7.0, both boots.

A plane row at each detached bind's root is not built. Such a design would also need to pin those objects and
prove that its neutral Landlock rules do not widen the domain. The startup snapshot does not track later host
mounts or host ancestor renames. Alias checks compare the filesystem instance, not the data it exposes: a
separate network mount of one export, a FUSE mirror or a loop image can show the same data without being
recognised at any tier. Deny the other path too, or avoid mounting the same export twice where agents can read
it. Known network mount types with the same source string on different filesystem devices produce a warning,
not a refusal. Protected-name scopes receive no alias check. Hard links and overlay layers retain their stated
limits. At tier cgroup without a plane, `setuid: true` with a `deny_read` or protected-name rule remains
refused, including the built-in secret list; a narrower filter refusal of detached-mount creation is future
work (ADR 0011).

### what a later design must do

A later listener must decide the identity of the opened file within the denied tree, anchored at mounts the
listener holds, rather than compare a path read back from the event descriptor. Its identity and ownership model
must survive ancestor renames and approved filesystem operations and support an agreeing recorder. Candidate kernel
interfaces to evaluate, **not evaluated for this release**, are `FAN_REPORT_FID`, `FAN_REPORT_DFID_NAME`,
`FAN_REPORT_MNT`, `name_to_handle_at(2)`, `open_by_handle_at(2)`, and `statx(2)` mount ids (`STATX_MNT_ID`). Their
availability, portability and sufficiency are not established here. Refusing listener-decided aliases at startup is
a fail-closed release limit, not an implementation of that later design.
