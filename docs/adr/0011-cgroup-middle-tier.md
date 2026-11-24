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

## Amendment, 2026-11-19 (round 4, X2): a refusal is about the file, at every tier

Measured: in a Windows 11 guest with WSL (row `W-E4-ALIAS`, run 2), inside an enforcing run with the default contract
at tier landlock, `/home/probe/.ssh/tego-proof-decoy` was refused and recorded, and the same file was read through
`/mnt/wslg/distro/home/probe/.ssh/tego-proof-decoy`: WSLg mounts the distribution's root filesystem a second time
there (same device, root `/`, read-only). The record showed one refusal. This was the limit GAPS C68 stated for tier
landlock (another name beneath a readable folder, E32 (ii)); it holds on any Linux machine where the mount table shows
a denied file on the same filesystem instance under a second name beneath a readable folder: a bind mount of the home
or of a part of it, a btrfs top-level volume mounted beside its subvolumes, a container volume bound twice. Released
v0.1.3 has the same code path (by source: compile adds no other names; its GAPS C68 states the limit); not run.

Decision. At compile, after every pass that adds a deny entry, each deny entry is applied to every other name the
mount table gives the same file (`compiler.denyAliases`, `mountTable.otherNames`), on every system, from mountinfo
alone: a row of the same device whose root lies at or above the entry's place shows it below that row's point (a bind
of it, of a directory above it, of the whole filesystem, as `/mnt/wslg/distro`), and a row whose root lies beneath it
shows that part at its point. Covered: every `deny_read` entry (declared, built in, tego's own, `fs.ask_read`, the
built-in refusals' read targets), every built-in row absent at compile (its ungranted name under each other name of
its directory) and every `deny_write` entry whose other name lies beneath a write entry. Each added entry has the
original's kind, `Raw` and position, so it carries the same rule name (a built-in one is named by the original's path,
`FSRule.AliasOf`). A name is added only when it reaches the same file now (device and inode, links followed); one that
reaches another file is a covered mount, whose content a run cannot uncover (Landlock forbids mount changes). Tier
landlock's ruleset then leaves the other name out of the read grants as it leaves out the entry, the supervisor decides
and records a read there by the entry, and an added name beneath a write entry is unenforced and held like any nested
deny; a write entry at exactly an added name is a contradiction. Landlock's allow-list model needs nothing else: the
enumeration descends to the added name, so no read grant of any contract reaches it. Where the table cannot list every
other name (a mount that cannot be placed; in this process's own table, an unlinked directory root, or one whose type
statx cannot establish, on the entry's device) compile warns once, with how many entries that touches. Names a table
cannot give (another filesystem instance of the same data, a FUSE mirror, hard links) stay as C68 says. The root
tiers' startup refusal of an alias the listener cannot hold is unchanged. Doctor's home alias warning says that tier
landlock applies each entry to the second place. *Replaced by round 5 (below):* `denyAliases` is now `mountAliases`;
write entries get their other names too, every deny_write target gets every other name wherever it lies (not only
beneath a write entry by path), the name rules get theirs, and a list the table cannot complete refuses the contract
instead of warning.

Tests: `TestOtherNamesOnWSL` (WSL's table, `pkg/spec/agent/testdata/wsl-mountinfo`, reconstructed from the guest's
measured rows: the next run of `W-E4-ALIAS` captures the whole table), `TestOtherNamesOfBinds`,
`TestCompileDeniesEveryName` (a bind stand-in: the built-in `~/.ssh`, a declared entry and an absent row each get the
second name with the same rule; a read there is refused by the entry; a covered name is left out). Each failed first
without the pass. The conformance cells `mounts-bind` (read-bind-alias-nested), `mounts-bindsub`, `mounts-bindfile`
(two cells) and `mounts-bindhidden` now expect a refusal at every tier; `mounts-bindmove` and `mounts-bindancestor`
keep their landlock exception until a root guest measures them (their names lie beneath a write entry, where held
reads decide). Root-guest runs of all seven owed.

*Measured 2026-11-19 (Ubuntu 25.10 guest, kernel 6.17, lockdown none; the WSL branch's run before pass 14):* at tier
landlock the kernel refused (EACCES) the three cells that kept the exception: `mounts-bindancestor`'s
`read-after-rename-through-bind` and `read-after-exchange-through-bind`, and `mounts-bindmove`'s `read-moved-alias`. The
refusal is right and the cells were outdated: the bind that holds `secret/deep` is moved with its parent, but what is
read through it is still the `deny_read` target's inode, which the held-read pins refuse by identity (ADR 0069), and E32
(ii) no longer describes tier landlock's reads of a name the mount table shows (round 4 above). The rename's refusal
names the rule (`fs.deny_read[./secret/]`); the exchange of two directories is one the pins cannot follow, so they
latch and refuse every held read under `held-read-identity-unknown` (ADR 0069: fail closed). A refusal of a file that
is still the denied one by identity is never turned into an allow; the cells say refused at every tier, with that
reason for the exchange at tier landlock, and the `exception` is gone from both fixtures.

## Amendment, 2026-11-19 (round 5, Y1, Y2, Y5, Y6): every entry's other names, from one computation

The adversarial review of round 4 (NOT CONFIRMED) showed that round 4 gave other names to deny entries only, and so
could not keep its own words ("every deny entry is covered"): (F1) a deny_write target beneath a write entry was
given another name only when that name lay beneath a write entry by path, but Landlock keys a write grant to the
inode, so with the home or the project bound read-write elsewhere `/srv/u/proj/.git/hooks/pre-commit` was writable
through the bind while the floor (`RuleTable.DenyWriteTarget`, by spelling) and the decision model said "refused";
(F6) a deny_read target inside a write entry had its other name labelled enforced; (F2) the name rules (`.env`,
declared deny_read globs, the built-in home paths) had no other names, so a `.env` made during the run was read under
`/mnt/wslg/distro/...`; (F5) a mount table that could not be read, or could not list every name, only warned; (F7)
live blocks matched by spelling.

**The requirement.** At every tier and in every `fs.reads` mode: no read of a deny_read file and no write of a
deny_write target (built-in or declared) succeeds through any name the mount table shows for it, and neither the
record nor the decision model says "refused" for an operation the kernel allowed.

**Decision.** `compiler.mountAliases` (`pkg/spec/agent/compile_alias.go`) replaces `denyAliases`. Every entry's other
names come from ONE computation, `compiler.otherNamesOf`: the table's rows of the same filesystem instance (a bind of
the path or of a folder above it, of the whole filesystem as `/mnt/wslg/distro`, and, for a deny entry, a bind of a
part of its tree elsewhere), each name confirmed now by device AND inode (`compiler.sameFile`); a path that does not
exist yet is named under each other name of its nearest existing ancestor. What each kind's names become is what the
kernel makes of them:

- A write entry's other names are write entries (same rule name, `FSRule.AliasOf`), because Landlock grants by inode.
  `underWrite`, `aliasUnenforced`, the Landlock builder's nesting (I5) and `decide.LandlockRuleset` all see them, so a
  write through a bind of a write entry is modelled as allowed (it is), and a deny entry beneath one is nested and held
  like any other. A bind of a part of a write entry elsewhere carries no grant (the kernel's walk from it never meets
  the entry's inode) and is not a write entry. A deny_read entry the contract names only under the other name of a
  write entry (the write entry declared through the bind) is nested too; a built-in row absent at compile beneath it
  is left out, as beneath any write entry; a write entry's other name at exactly a deny_read entry is a contradiction.
- Every deny_read entry and every built-in row absent at compile gets each other name, as in round 4, with the same
  rule name; one beneath a write entry or another name of one is unenforced at tier landlock and held.
- Every deny_write target, built in or declared, gets each other name wherever it lies (not only beneath a write
  entry), so the supervisor's floor, which matches by spelling, refuses a write there as at the original, under the
  original's rule; one beneath a write grant is unenforced as the original is.
- The name rules the held-read floor matches by name (`Reads.Patterns`, `Reads.Names`, their exemptions) get the other
  names of each rule's scope roots (`HeldReads.Aliases`): the floor asks a held read under an alias as the name it
  shows too (`decide.HeldReadIndex`), so a file made during the run is refused under every name.
- Where some other name of a denied file is one no layer refuses in the contract's mode, compile refuses the contract
  with one sentence that names the file, the other name and the setting that makes it enforceable
  (`compiler.otherNamesEnforced`): under `fs.reads: direct` a deny_read target's other name inside a write grant
  (nothing holds reads at tier landlock), and a deny_read entry beneath another name of an `exec.allow` directory
  (its grant carries read access). The entry's own name keeps its warning: the contract names it.
- Fail closed: a mount table that cannot be read or parsed refuses every contract with the reason (no fs section and
  `fs: {}` included), and so do the other names of a deny entry or a name rule's scope that the table cannot all
  list (a visible unlinked directory root on the device, a mount that cannot be placed; a mount hidden under another
  never counts, round 6 below). A disabled probe
  (`WithMountInfo("")`) adds nothing, by the caller's choice. A deny entry the compiling person cannot look at (a
  folder above it they may not search) has no name that could be confirmed as its other name and is not doubted.
- A live block (`tego block`, every live rule) covers the other names of its file by the same computation
  (`agent.OtherNames`), taken when the launcher first sees the block, under the block's own rule.

**Limits, plainly.** Mounts made after a run starts are not seen: compile reads the mount table once, before the run,
and a live block reads it once, when it is added. A bind made later (by the host, or by WSL after the distribution
started) shows a denied file under a name no rule covers until the next run (GAPS C68). A live block whose other
names the table could not all list when it was added covers the names it could list, and says so (round 6 below).
Other names a mount table
cannot give (another filesystem instance of the same data, a FUSE mirror, hard links, overlay layers) stay as C68
says. Through a read-only bind (WSLg's `/mnt/wslg/distro` is one) a write the write entry's grant allows is refused by
the mount (EROFS); the model says the grant allows it, never that a rule refused it.

Tests (each shown failing on `c012a53a0` first): `TestCompileDeniesEveryName` and `TestCompileWriteEntryOtherNames`
use a bind stand-in that gives the same device and inode under two names and resolves each to itself, as a bind
does (`withFileIdentity`), with names that differ in the device alone or the inode alone left out (a mutation of
`sameFile` that ignores either turns them red); `TestCompileRefusesAnOtherNameNothingRefuses`,
`TestCompileFailsClosedOnTheMountTable`, `TestSetMatchesEveryOtherName` and `TestLauncherBlocksEveryOtherName`. The
conformance fixture `mounts-bindwrite` (new) holds a real read-write bind of a write entry with a nested deny_read and
a declared deny_write target, read and written through both names, at tier landlock and the root tiers; it and the
five round-4 cells are owed to a root guest.

## Amendment, 2026-11-19 (round 6, Z1, Z3, Z4): hidden mounts, live blocks that say so, absent rows under an exec directory

The adversarial review of round 5 confirmed it with findings.

**Z1 (G1, High): fail closed must not refuse ordinary setups.** Round 5 doubted a whole filesystem when any mount on
its device had an unlinked root whose type statx could not establish. A mount hidden under another answers statx with
the mount on top, so the check could never establish its type: systemd-nspawn binds a deleted file over
`/proc/sys/kernel/random/boot_id` from its `/run` tmpfs, one row of which sits under the `/proc/sys` bind, and every
path on the container's `/run` was doubted. Every contract has built-in deny entries on `/run` (`/run/user/<uid>`, the
docker socket, `/run/WSL`, ...), so every compile in nspawn (and `machinectl`, Fedora `mock`, mkosi) was refused. The
rule now, in `mountTable.unlinkedOn` and the public alias query: **only a visible mount counts.** A mount hidden under
another shows nothing under any name, so its unknown type never puts the filesystem it sits on in doubt. A visible
unlinked directory root, or one whose type cannot be established, still does, and the refusal names the mount, says why
(its root was deleted or cannot be read) and says what to do (unmount it, or run where it is not mounted). Tests:
`TestHiddenMountsNeverDoubtAFilesystem` replays every captured mount table in the repository (Docker, containerd,
Podman, bubblewrap, toolbox, snap, WSL2, desktop, chroot, nspawn, and this machine's own table, `desktop-live`) as the
calling process's own with statx faked as the kernel answers, and asserts no device is in doubt; `TestNspawnLiveTableListsTheRunNames`
and `TestVisibleUnlinkedDirectoryStillDoubts` (the rule is about hidden mounts only). Red on `3b98946a1`: the two
nspawn tables.

**Z3 (G3): a live block says when its list is short.** A path, read or write block whose file's other names the mount
table could not all list (`agent.OtherNames` returned an error) still applies to every name found, and now says so
twice: `tego block` prints one sentence naming the file and the reason (and that a name made by a mount not in the table
stays open), and the run's launcher writes one `gap what=enforce why=live-block-partial` line for the block (once per
add; `binary` is the value, then the reason) beside its `live-block-added` line (spec/record/v1/README.md). The gap is
a gap proper (the views count it as one the run lacked), not an operator action. Tests: `TestLiveBlockSaysWhenItsNamesAreShort`
(`internal/runtime`), `TestBlockSaysWhenTheMountTableCouldNotListEveryName` (`internal/cli`).

**Z4 (G4): a built-in row absent at compile, beneath another name of an `exec.allow` directory.** The directory's grant
(`READ_FILE`) sits on its inode, so a file made under the other name is readable; `execDirs` drops the row under the
directory's own name only, and the row the alias pass placed under the other name stayed, so the decision model said
"refused". `otherNamesEnforced` now refuses the contract, as it does for an existing deny_read entry there, with one
sentence naming the file, the other name and what to change. Test: `TestCompileRefusesAnAbsentRowUnderAnExecDirectorysOtherName`.
