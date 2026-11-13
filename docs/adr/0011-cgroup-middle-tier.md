# ADR 0011: a `cgroup` middle tier gives root users the hardened features without a boot change

Status: accepted 2026-09-21. Supersedes ADR 0002's two-tier statement.
Amended by ADR 0021 (accepted 2026-09-29; fanotify's arming point and no process start under marks) and ADR 0024 (accepted 2026-09-29; the plane backend is built in tier 2; tier 2 decides opens, execs and mutations in the kernel; fanotify becomes the fallback).
Amended by ADR 0042 (accepted 2026-10-05): tier `cgroup` is reached by a root launcher; "or file capabilities" is conditioned.
Decision: three tiers. `landlock` (no root); `cgroup` (root or file capabilities, no boot parameter): cgroup-attached socket programs (`cgroup/connect4,6`, `sendmsg4,6`, `bind4,6`, `connect_unix` on 6.7+) for network by host:port and UDP per cgroup, fanotify `FAN_OPEN_PERM`/`FAN_OPEN_EXEC_PERM` for path-aware open and exec deny with reasons, Landlock inside the run for delete, rename and mkdir, the full eBPF record and uprobes, adoption of daemon-created cgroups; `bpflsm` (adds `bpf` in the LSM list): delete, rename, mkdir, chmod, mknod per cgroup, `ptrace` and `bpf` hooks, in-kernel reasons on every hook.
Why: every attach type exists in the kernel headers (verified), and `IPAddressDeny=` in systemd proves the cgroup socket family works on stock distributions; fanotify permission events exist since 2.6.37/5.0 with errno replies since 6.13. Production servers get the middle tier with `sudo` on day one; only Ubuntu-family images need the boot line for the top tier (Debian 13, Fedora, RHEL 9/10, Amazon Linux 2023 already list `bpf`).
Consequence: `tier:` enum is `auto | landlock | cgroup | bpflsm`; fanotify open/exec deny is a userspace round trip on every open and is benchmarked separately; delete and rename inside adopted containers are a tier-3 property.

*Amended 2026-10-05 (ADR 0042 (2), (3)(c)):* tier `cgroup` is "root (a root launcher)" in this release. "Or file
capabilities" is not delivered: a file-capability copy of tego is refused at start with exit 125
`[privileged-path-unsupported]`, and the path may return only for single-administrator hosts by its own ADR, once
ADR 0042 (3)(c)'s five conditions hold.

*Amended 2026-11-11, corrected 2026-11-12 (mount aliases, fix rounds 2 and 3):* the fallback listener decides an open
by the path read back through the event descriptor. A bind mount can expose a `deny_read` tree, or part of it, at
another path. A mark on the declared mount does not cover that other mount. Adding the other path to the listener's
policy is insufficient: a path can change when an ancestor is renamed, including through another bind or an approved
filesystem operation. This release stops trying to hold aliases by their path strings.

Decision for this release: wherever the listener would decide a compiled `deny_read` path entry, `Prepare`
refuses the run if `agent.MountTable.TreeAliases` finds another place on the same filesystem instance where
that tree or part of it is visible. This applies at tier cgroup without a plane mode and after a plane's
fallback to the listener. No flag overrides it. Diagnostics name the first matching entries and places, why
the listener cannot hold the rule there, and a remedy; omitted entries and places are counted. They are
collected in a flat slice and joined once, so rendering a refusal does not repeatedly copy every preceding
diagnostic (`TestListenerAliasDiagnosticsBoundLargeInventory`). The host owner can remove the duplicate mount.
For whole-tree aliases only, a selected decision plane that holds the contract is another remedy. Advice to
use cgroup after a plane refusal is conditional on its listener holding the contract, and names a detected alias
that prevents it. The listener adds no alias
deny spellings or alias marks and has no path-based movable-ancestor exception.

The decision plane is unchanged: its dentry walk holds whole-tree aliases on the same filesystem instance,
including binds of a parent or of the whole filesystem. It cannot hold a part of a denied tree mounted outside
that tree. Such a table falls back at tier cgroup, whose listener now refuses it, and is refused at tier
bpflsm (ADR 0025). Selecting tier cgroup is therefore no remedy for a detached part.

Each `Prepare` acquires one mount-facts object shared by composition, listener policy and marks, plane
holdability, and recorder startup, including boundary adoption. Acquisition is bounded to 8 MiB and 32,768
records, validates whole records and the mount graph, and requires two equal reads, with at most three
attempts (`agent.ReadMountSnapshot`). Mount lookup follows mount and parent ids and is checked against statx
mount ids. Unreadable, malformed, changing or unverifiable facts refuse the run wherever its rules require
these facts (`ErrMountTable`). Equal reads detect changes observed during acquisition; they do not freeze the
host's mount topology or exclude an ABA change. The recorder receives the devices the ordinary listener
actually marked, including submounts beneath ordinary entries. There is no alias-decision handoff: a run with
detected aliases of listener-decided path entries on the same filesystem instance never starts. A device number
still cannot distinguish different mounts of that filesystem. Since 2026-11-12 this is the same reader, record parser, graph check and
parsed table compile uses (ADR 0059, "Compile-time mount boundary", the one-reader amendment): its visibility lookup
by parent edges is the shared holding-mount lookup, and its overlay layer guards apply here too. Several top
candidates at one mount point remain unknown before live statx verification, even if statx identifies one of them.
The supplied and live forms are pinned by `TestMountAmbiguousSiblingsRemainUnknown`; merged-path kernel checks
remain owed in a guest.

A `setuid: true` contract with a `deny_read` or protected-name rule is also refused wherever the listener decides
(`ErrListenerSetuid`). The built-in secret list adds these rules, so the ordinary built-in contract needs a decision
plane in this combination. Reasoned from kernel and filter sources, not guest-tested: an allowed setuid program can
regain mount privileges and create a detached copied mount outside the listener's marks. The filter's refusal of
`move_mount` is not enough. Refusing detached-mount creation syscalls in the filter would be a narrower alternative;
it is future work and has not been guest-tested. A plane is an option only if it holds the whole contract.

Evidence: `TestListenerRefusesEveryAliasLayout` and `TestListenerAliasDiagnosticOncePerEntry` cover refusal
before kernel loading, one diagnostic per reported entry, whole-tree plane handling, detached-part fallback,
and the absence of alias decisions and marks. `TestBindAliasesThatCannotBeListedRefuseTheRun`,
`TestPrepareSharesOneMountSnapshot`, `TestRecorderUsesPreparedMountFacts`,
`TestMountSnapshotFollowsSymlinkSpelling` and `TestSetuidRefusesReadsOnlyTheListenerHolds` cover the other
preparation boundaries with unit tests. These are unit claims. The changed conformance expectations are owed
in a guest on Debian 13's 6.12 and Fedora's 7.0, both boots. Earlier guest evidence is narrower:
`mounts-bindmove` and `mounts-bindhidden` failed before fix round 1, while `mounts-bindsub` passed before and
after. Source inspection shows that its built-in project name scope masked the extra-line omission.
`TestOrdinarySubmountListenerHandoffEmitsOneRefusal` now uses an ordinary entry and a different-device
submount outside all name scopes, with the actual listener's marked-device handoff (unit proof).

Tego identifies other places of a denied folder by the identity of the filesystem instance. A different
filesystem instance showing the same data, such as a second network mount of one export, a FUSE mirror or a
loop image, is not recognised at any tier. Deny the other path too, or do not mount the same export twice
where agents can read it. Known network mount types with the same source string on different filesystem
devices produce a warning, not a refusal or a claim that they share data. Protected-name scopes receive no
alias check. Other limits remain in enforce-cgroup-observe §6 item 24: later host mounts and host ancestor
renames are not tracked by the startup snapshot; hard links and overlay layers are outside these alias facts.
Tier landlock's stated alias limitation is unchanged.

### what a later design must do

A later listener design must decide whether the opened file is inside the denied tree by file identity, anchored
at mounts the listener holds, instead of by a path read back from the event descriptor. It must keep that identity
valid through ancestor renames and approvals, define mount and descriptor ownership, and give the recorder the facts
it needs to agree with the decision. Candidates to evaluate, **not evaluated for this release**, include
`FAN_REPORT_FID`, `FAN_REPORT_DFID_NAME`, `FAN_REPORT_MNT`, `name_to_handle_at(2)`, `open_by_handle_at(2)`, and
`statx(2)` mount ids (`STATX_MNT_ID`). Listing them asserts neither availability on a supported kernel nor sufficiency
for that design. The startup refusal is a fail-closed limit, not that design.
