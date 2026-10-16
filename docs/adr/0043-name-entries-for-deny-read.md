# ADR 0043: name entries for `deny_read`: what one decides, how it matches, where it applies (amends ADR 0039)

Status: accepted 2026-10-05; the compiler and the decision core (C2 to C4) built 2026-10-05; the kernel (C5, C6) built 2026-10-17; enforced in every build since 2026-10-27 (C0, C7's clears, C8, C9's capability, doctor's cells and compile's print, C11's switch removed). Not built as a whole, with two items open: C10's per-open budgets are not built (non-matching open +30 ns, matching 1 us p50: measured once, inside the suite's noise; fill, the warm start and kill test 4 hold with the flag set; Implementation notes, "Not done in the name backend"), and a lsm program misses the 6 ms verification limit (the base missed it too; Implementation notes). The guest results below are an earlier build's, and the last implementation note lists how this tree differs: on that build C10's matrix rows ran and pass (6.17, RHEL 9, AL2023 6.1, Ubuntu 24.04, Debian 13, Fedora 7.0), the compacted table's bpflsm run passes, and C9's conformance name space passes on every axis, its baseline `[]`; on this tree the root cells, the matrix rows, the compacted run and C10's figures await the KVM run. D10 takes the built-in scoped, D1 keeps the creation refusal, and D3, D5 and the glob widening stand, with the built-in pattern unchanged.

**Amends ADR 0039**: decision 1's row value ("up to four scope inodes") and its 64-entry inner map (65 here), decision
2's scope test, hook list and fault rule, decision 3 ("exact final names only"; its precedence sentence), decision 4's
compaction rule, the stated semantic difference ("at tier bpflsm ... at tiers landlock and cgroup it does not"), the
capability wording (`deny_read.created_later: enforced`) and the Consequence's "its own write of one goes ahead". ADR
0039's purpose, its per-slot inner map by `run_idx`, its gen and identity rules, its Why and its rejected options
stand. When built it amends SEMANTICS §1 and §2; agent-contract R5, R6, R7, R20; enforce-plane §2.2, §2.4 (cap and
condition 7), §8 invariants 4 and 10, R5 to R8, R10, R13, R21, R23 to R25, R28 and E13; enforce-cgroup-observe's open
rule and R8 (marks); supervisor R15 and R15d and the approval completion; `spec/record/v1` (rule forms,
`capabilities`, `record_minor`); record-ledger §2.2; limits-check-doctor-cli (doctor's cells, the capability row);
`docs/OPERATIONS.md` ("Row caps", "Cost per open"); CAPABILITIES.md. ADR 0039 carries `Amended by 0043` under its
Status line.

Written 2026-10-05. Facts marked [measured] were checked in a throwaway clone; [documented] cites the
code; [inference] is reasoning.

## Context

ADR 0039 (accepted 2026-09-30 as a design, not built) adds a row kind keyed by a file's final name and scoped to a
subtree, so a `.env` file written after compile is refused at tier 3 and the per-file rows of a project with many of
them stop exhausting the plane. Checking the accepted text against the code, and the proposals made for it against both, found:

- **F1. The accepted scope test cannot see the scope.** The walk stops at the first current row
  (`bpf/decide.bpf.c:189-201`). Decision 2 asks "whether any inode the walk already visited is one of the row's
  scopes", but with `fs.write: [./src]` the walk from `./src/.env` stops at `./src`, below the project scope.
  [documented]
- **F2. The built-in pattern is a prefix, and never a directory.** The scan matches `.env` and every `.env.*` but
  `.env.example|sample|template|dist` (`pkg/spec/agent/compile_fs.go:854-866`); a directory named `.env` (a Python
  virtualenv) is descended, not matched (`:808-813`). [measured: a `sub/.env/bin` tree compiles with no entry for it]
  Exact names only (decision 3) would leave `.env.local` and every later `.env.<x>` uncovered.
- **F3. The scan never enters dependency or VCS directories**: `.git`, `node_modules`, `vendor`, `target`, `.venv`,
  `venv`, compared case-exactly (`compile_fs.go:73`, `:809`). [inference] npm's default ignore list does not exclude
  `.env`, and published packages carry such files; a name entry that entered these directories would refuse
  installing, reading and removing them.
- **F4. A `deny_read` entry already refuses modifications at the plane.** The root model allows a modification only
  under a write entry (`internal/policy/decide/evaluator.go:176-192`), so the expansion's entry at an existing `.env`
  refuses writing, truncating, deleting and renaming it at tiers cgroup (plane) and bpflsm today. Decision 2 ("acts
  as ... the compile-time expansion's own entry at that path would") and the Consequence ("its own write of one goes
  ahead") cannot both hold; under the second, dropping a covered row (decision 4) would allow writes the row refused.
- **F5. The accepted "way out" does not exist.** `fs.write: [./.env]` on an existing `.env` is a compile
  contradiction (`deny_read … is also a write entry`, `compile_fs.go:634-641`) [measured with the package's own
  fixture]; a write entry that does not exist is created as a directory at Prepare
  (`internal/runtime/enforce/landlock/fs.go:41-56`) [measured: `fs.write: [./.env.test]` compiles `Missing`].
- **F6. Tier cgroup in a plane mode runs the same bodies** (`TEGO_PLANE_HOOK`; enforce-plane R25; ADR 0019's
  2026-09-29 note). "At tier bpflsm only" would need a mode switch in every body and a split column.
- **F7. No new fill kind fits.** The wanted-row key gives the kind two bits and all four values are taken
  (`bpf/include/events.h:842-848`, `TEGO_FILL_LISTEN = 3`). fs rows have spare bytes (`tego_plane_row.pad`,
  `:693`; `tego_plane_fill_row.pad`, `:889`).
- **F8. The recorder recompiles the rows** from the run's RuleTable to name refusals
  (`internal/runtime/observe/plane.go:33-43`): whatever decides which rows exist must be a function of the RuleTable
  alone.
- **F9. A run's capability line is one boolean per CAPABILITIES row**, "`true` only for what this run could do",
  every row written (`spec/record/v1/README.md:38-40`): partial enforcement is `false` with prose in the matrix.
- **F10. Exec name rows compare bytes exactly by contract** (`bpf/include/plane_name.h`, enforce-plane R9) and share
  the exec map's 1,024 rows; name-keyed denies must not change them. The exec name pass already masks the bytes past
  `d_name.len` (`tego_word_mask`, `plane_name.h:51-75`).
- **F11. The tier-2 fallback already refuses mutations the root walk refuses.** With no plane, the supervisor sets
  `enforce` on every refused non-read fs verdict at tier cgroup and answers `EACCES` before the syscall
  (`internal/runtime/supervisor/fs.go:643` `fallbackMutation`, ADR 0021 (5), ADR 0028 S3); the verdict comes from
  `decide.AdvisoryFS` (`internal/policy/decide/advisory.go:261-330`), whose tier-cgroup branch asks
  `listenerOpenRefused` for write-opens (reason `read-denied`) and `rootAnswer` for every other mutation. The nested
  `deny_read` conformance cells pass on the fanotify axis with `test/conformance/testdata/baseline.json` equal to `[]`.
  (supervisor R15's "an unlink, rename, mkdir, symlink or link ... keeps the Landlock verdict" predated this; R15's
  2026-10-17 amendment corrects it, with agent-contract R15's "stays Landlock's".) [documented]
- **F12. The listener does not handle an unlinked file's path.** It decides on `os.Readlink("/proc/self/fd/N")` of the
  event's descriptor (`internal/runtime/enforce/cgroup/fanotify.go:935`) and matches the raw string
  (`policy.go` `decideOpen`, `decide.ListenerOpen`); the kernel appends `" (deleted)"` when the opened dentry was
  unlinked or renamed over, so `/p/.env (deleted)` is beneath no entry at `/p/.env` and the open is allowed. Other
  readers of `/proc` links strip the suffix (`internal/platform/proc/proc.go:146-153`); this one does not. A
  pre-existing defect for every file-level `deny_read` entry, the `.env` expansion included. [documented]
- **F13. An approved open is completed outside the plane.** The supervisor opens the held object itself
  (`internal/runtime/supervisor/ask_open.go:331-360` `completeHeldAskOpen`, then `SECCOMP_IOCTL_NOTIF_ADDFD`), outside
  the run's cgroup, for `fs.ask` (`ask_open.go:290-328`) and gate-held opens (`gate.go:209-241`). It refuses a
  nearer `deny_read` on `h.resolved` before the hold (`ask_open.go:310`, `gate.go:209`) and re-checks only
  `askScopeValid` after the wait (`ask_open.go:353`). [documented]
- **F14. Compile records a mount point only for directories** (`compile_fs.go:684-688`: `IsMountPoint = isPoint &&
  fi.IsDir()`), while `mountTable.lookup` reports a file mount point too (`pkg/spec/agent/mountinfo.go:113`). At a
  mount root the dentry's own name is the source's (a file bind-mounted over `.env` is opened as a dentry named after
  its source), not the path component. [documented]
- **F15. The listener marks every mount point beneath a `deny_read` entry** and refuses Prepare with `ErrMountTable`
  when the table cannot be read (`policy.go` `newPolicyWith`, enforce-cgroup-observe R8, I7). [documented]
- **F16. The record's `rule` is "the declared entry or `unmatched`"** (`spec/record/v1/README.md:55`), and `tego
  drift` builds its declared set from `rt.FS`, `rt.FSAsk` and the net and exec tables only
  (`internal/check/drift/drift.go:512-537`), built-ins as auxiliary entries. [documented]
- **F17. A missing rows map fails closed today.** A live header whose slot has no rows map refuses `path-unresolved`
  and counts `norows` (`decide.bpf.c:241-252`, `TEGO_WALK_NOROWS`); the slot header is 16 bytes
  (`events.h:613-618`). [documented]

## Decision

### Terms, and what becomes a name entry

A **name entry** is compile output, `RuleTable.NameDeny` (not contract input: the contract hash is unchanged): a
literal final name, exact or literal prefix, ASCII-folded; the **scopes** it applies beneath (directories, by
canonical path, each with the spelling compile used); its rule (D8); for the built-in only, its exceptions. A file is
**covered** by an entry when D2 matches its final name and D4 places it beneath one of the entry's scopes and D3
does not exempt it.

A **dependency directory** is a directory whose name is one the built-in scan skips (`.git`, `node_modules`,
`vendor`, `target`, `.venv`, `venv`), **compared case-exactly, as the scan compares it**; one list
(`agent.EnvSkipDirs`), shared by the scan, `NameIndex` and the config row. Where a directory on the path is the root
of a mount, its name is the mountpoint's (the dentry the walk crosses to), never the mount root's `/` or its source's.

- **The built-in `.env` list** (whenever `deny_read` is not `[]`): exact `.env`; prefix `.env.` with exceptions
  `.env.example`, `.env.sample`, `.env.template`, `.env.dist`; scopes per D10. A scope of an entry beneath another
  scope of the same entry, with no dependency directory between them, is dropped.
- **A declared `deny_read` glob** whose expansion was whole and whose final component is a literal (`secret.json`)
  or a literal followed by one trailing `*` (`.env*`), the literal free of `*?[\` and at least **2 bytes** for an
  exact form and **3 bytes** for a prefix form: one entry whose scope is the glob's literal base, the longest
  leading run of components with no glob character, resolved; it must exist. Any other final component (`*.pem`,
  `a?c`, `[ab]x`, a bare `*`, `k*`) gets no entry and keeps today's expansion, and compile says so on the entry's
  line; `**` stays refused. A glob a profile declares counts like the contract's own (R5 never drops a `deny_read`).
- A **name-eligible entry** is the built-in pair, or a declared glob that meets the rule above. D7's capability is
  true only when every name-eligible entry of the table is in `NameDeny`.

**Caps per run**: 64 name rows (exact, prefix, exception and exemption-only rows, D3), 8 arms a row, 8 scopes
(exemption parents included), 4 distinct prefix lengths, 8 leads (D2). **Allocation order**: deny entries first, the
built-in exact entry, then the built-in prefix entry, then declared entries in declared order; each entry is given
the rows, arms, scopes, leads and prefix lengths it needs together with those of every D3 exemption that applies to
it. An entry that does not fit whole, with its exemptions, or whose name key collides with a row already allotted
(D9), is **left out of `NameDeny` whole** (so `Evaluate` and the plane agree), keeps its compile-time expansion, and
`compile` warns `unenforced`, naming the entry and the cap or the collision. A name entry left out never lowers
protection below today's expansion, which is why this is a warning and not E13's refusal; it makes D7's capability
false. An exemption is allotted only with a kept deny entry, so no table is refused for its exemptions.

### D1. What a name entry decides

A covered file is decided as if the expansion had made a `deny_read` entry at its own path (ADR 0039 decision 2's
own words, which F4 shows is what that entry decides):

- a **read** is refused, `read-denied`;
- a **modification of its content or its name** is refused with the hook's modification reason: a write-open,
  `O_TRUNC`, its creation (`O_CREAT`, `mknod` of a fifo, socket or device, `symlink`, a hard link's new name, a
  rename's destination, an `O_TMPFILE` file linked to the name), truncation by path or by descriptor, unlink, and a
  rename of it at either end, `RENAME_EXCHANGE` included;
- a hard link or rename whose **source** it is takes REFER strictness 2 (enforce-plane R10).

**Metadata is not decided**: the attribute hooks (chmod, chown, xattr, ACL, `chattr`) keep protecting `deny_write`
targets only (R12), so the agent can, for example, make a covered `.env` world-readable or change its owner. A name
entry **never decides a directory**: a directory named `.env`, its creation, listing, removal and rename, and
everything beneath it, are decided as if the entry did not exist (D5 alone adds a rule for directory renames). It is
not consulted by `bprm_check` (an exec of a covered file fails at its `file_open` read), step C or the socket hooks.

**A name entry decides only what the walk allows.** Where the nearest-wins walk already refuses the question (a
`deny_read` directory above, a `deny_write` target above, the file's own expansion row), the verdict and the rule are
the walk's; the name check is not run.

What D1 protects, stated exactly: an existing covered file's content and name, and the agent's own creation of a
file at a covered name. It does not protect a path from coming to hold agent content by a **directory** move or swap
that brings files into coverage (D5 allows moves into coverage; Residuals), nor a file's metadata.

### D2. Matching

The object's final name is compared after **ASCII case folding** (bytes `A`-`Z` to `a`-`z`; every other byte exact):
an exact entry matches when the folded name equals its literal; a prefix entry when the folded name starts with its
literal (the literal itself included) and is not one of its exceptions. No suffix, infix, single-character or class
form; no Unicode folding or normalization.

**The object's final name** is `d_name` of the dentry the hook holds (for a creation, the new name), except when that
dentry is the root of its mount and the mount is not the namespace root: then it is the mountpoint dentry's name, the
one the walk crosses to (`struct mount`'s `mnt_mountpoint`). A file bind-mounted over `.env` is therefore matched as
`.env`, as the path the agent opened spells it and as `Evaluate` reads the path.

In the kernel a name becomes a candidate in two steps. A **prefilter** compares the name's first eight bytes,
**masked to `d_name.len`** with `tego_word_mask` (an inline `d_iname` keeps stale slab bytes after its NUL, so an
unmasked word would make a short name such as `.env` miss) and folded, with the slot header's leads (each literal's
first min(8, n) folded bytes, its length and the minimum name length); a name passing none is decided without a
lookup. A candidate is looked up in the slot's name rows: one exact key over the whole folded name, one prefix key
per distinct prefix length not longer than the name; a hit counts only when the folded, masked bytes compare equal,
so a key collision matches nothing. Exec rows and their byte-exact compare are untouched (F10). The built-in scan's
own predicate is unchanged (case-exact); `FuzzEnvNameRuleMatchesScan` holds that every name the scan matches, the
built-in entries match, and that they match nothing the scan would not match folded.

**Failure paths.** The name pass's byte reads have no fault signal on the rdonly build (an exception-table load reads
0) and are bounded loops over at most 32 words; the hook holds the dentry inside the trampoline's
`rcu_read_lock`, so the name memory stays valid for the program. ADR 0039's "a name pass that cannot complete (the
reader faults) refuses" is withdrawn for the byte reads as unbuildable; on the probe-read build a failed
`bpf_probe_read_kernel` of a name word refuses `path-unresolved`. The **lookups do have failure paths, and each
refuses** (D9): a missing inner map, a missing or stale config row, a climb that cannot finish. A concurrent rename
by a process outside the run can show the name before or after the rename, or a torn length and address pair (the
agent's own rename of a covered file is refused); that is the outside-processes residual, not a fault.

### D3. Precedence

Only a declared `fs.write` entry **declared in the top-level contract file** (not in a profile it extends) whose
**resolved** path's final component, folded, is the object's folded name, and whose resolved parent directory is the
object's parent, beats a name entry. The place is taken from the write entry's resolved path, so a declared `./.env`
that is a symlink exempts its target's name in its target's directory, not the link's spelling. An ancestor write
entry never reopens a covered name, and **no `fs.ask` entry exempts one**: nearest wins at depth 0, as an ancestor
ask scope does not reopen a nearer `deny_read` row today. The exemption is by place and name, not by inode, so an
editor's atomic save (a temporary file, under a name no entry covers, renamed over the entry) or a delete and
re-create keeps it; a temporary name an entry covers (`.env.tmp`) is refused like any other.

An exemption **cancels every entry's arms for that folded name in that parent**: the built-in exact and prefix
entries and any declared entry (so `fs.write: [./.env.test]` exempts `.env.test` from the built-in prefix row
`.env.` as well). In the plane it is an **exempt arm** on the folded name's exact row (an exemption-only row when no
exact entry exists), scoped to the parent directory at depth 1; the parent becomes a scope row. The name check reads
the exact row first; an exempt arm whose parent is met at level 1 ends the check with no match.

The plane keys the exempt parent by inode, `Evaluate` by path: after a directory rename D5 allows (`mv app app2`), the
plane exempts `app2/.env` (the parent inode moved) while `Evaluate`, holding the compile-time tree, refuses it.
That is the same drift every inode-keyed row has after a rename (Residuals), on the allow side for the author's own
named file; the guest suite documents it with a cell.

`compile`: a write entry declared in the top-level contract file naming an existing file the built-in `.env` list
holds **drops that file from the built-in list**, with a warning naming both, as a declared write entry at a
built-in `deny_write` target's own path drops it from that set (agent-contract R20); a write entry from a profile at
such a path stays a contradiction (fail closed, as today, F5). A declared `deny_read` path or glob expansion at a
write entry's path stays a contradiction: the author wrote both. A declared write entry that does not exist is created
as a directory (F5), which no name entry decides; when its name would match one, `compile` says so ("to let the agent
use a .env.test file, create it before the run and name it in fs.write"). `compile` warns when an `fs.ask` entry
names a covered file: such an approval is refused without a prompt (interface 2).

Between name entries, the first in `NameDeny` order decides and names: declared entries in declared order, then the
built-in exact entry, then the built-in prefix entry, the order in which the expansion dedupes a path both cover
(agent-contract R6). (Allocation order, above, is a different order and decides only which entries fit.) A built-in
exception (`.env.example`) cancels only the prefix entry's arms.

### D4. Scopes and the climb

A file is beneath a scope when the scope directory is an ancestor on the path the kernel resolved, through mount
crossings as the walk crosses them (enforce-plane R7), **with no dependency directory strictly between** the scope and
the file (a scope that is itself inside or named like a dependency directory, such as a declared
`./node_modules/*/secret.json`, covers its own base; dependency directories nested beneath it are still excluded).
Each scope directory is a row: a complete, verdict-neutral row at its path (enforce-plane §2.4) whose spare byte
carries the scope's own bit (`tego_plane_row.scope`).

Membership is decided by a **second bounded climb that runs only after a name matched** (and for D5): the walk's
climb and mount crossing from the object, not stopping at rows. At a mount root it crosses to the mountpoint and reads
the mountpoint's name for the dependency test. It checks the identity and gen of every current row it meets as the
walk does (a mismatch refuses and is counted). It **stops as soon as every matched arm is decided**:

- an exempt arm is decided at level 1 (its parent is met there, which ends the check with no match, or is not);
- a deny arm is decided covered when one of its scopes is met with no dependency directory below it, and decided
  not covered when a dependency directory is met before any of its scopes (nothing above can cover the file);
- The climb stops outright when a dependency directory is met before any scope of any matched arm.

It fails as the walk fails: `BOUND` after `TEGO_PLANE_WALK_MAX` levels counted from the object, `UNRESOLVED`; a
name-matched object whose climb fails before its arms are decided is refused `path-unresolved` and counted. A scope
nearer than 64 levels is always met in bound, whatever the project's own depth or the other scopes of the run. No
scope row lies below the walk's nearest row (scope directories are rows, and the walk stops at the first row), so
below that row the climb needs no lookups, only the directories' names. The main walk, its rows and its verdict are
unchanged, and it runs first. The climb is its own global function, outside the `TEGO_PLANE_WALK` markers, so the
walk still reads no string (ADR 0024; `TestPlaneWalkHasNoStringOps` unchanged, *TestPlaneClimbIsOutsideTheWalk* new).

### D5. Directory renames

At the plane, a rename of a directory is **refused** (`rename-outside-contract`, `plane_reason: refer`, rule per D8)
when some name entry covers files beneath it at its old place under its old name and would not at its new place
under its new name: it leaves every scope of the entry, passes beneath a dependency directory, or takes a dependency
directory's name. With a positive destination directory the same is asked of that directory moved the other way
(`RENAME_EXCHANGE`; the 5.14 hook carries no flags, so a positive destination is treated as an exchange, as REFER's
reverse arm is). Both places are climbed from the parent directories the hook holds (`old_dir`, `new_dir`), with D4's
mount-root names, so moving a scope directory itself, renaming a directory within its scopes and **moving one into
coverage** (into a scope, or renaming a dependency directory to another name) stay allowed. The question is
coverage of the place, not the directory's contents: the kernel cannot list a subtree. A file rename needs no such
rule: D1 decides a covered file at both ends.

### D6. Compaction

`decide.CompilePlane` may drop a file's row (keys no inode, holds no descriptor, adds no neutral rule) when **all**
hold:

- (a) the table's keyed paths before compaction (`Keyed` and `NoFollow`; mounted roots, which Prepare adds, are not
  counted) exceed **`PlaneCompactAt`** (1024; a package variable that tests may lower, the product value fixed);
- (b) every entry at the path is a `deny_read` entry of the built-in `.env` list or of a declared glob that has a name
  entry in `NameDeny`;
- (c) a name entry covers the path (D2, D3, D4 by canonical path);
- (d) compile saw a regular file, not a symlink, with `st_nlink == 1`;
- (e) its filesystem gives a file one spelling: `ext4`, `xfs`, `btrfs`, `tmpfs` or `f2fs`, and on `ext4`, `f2fs` and
  `tmpfs` its directory does not carry `FS_CASEFOLD_FL` (a failing or skipped `FS_IOC_GETFLAGS` is a no);
- (f) the path is **not itself a mount point** (a file bind-mounted over it), and no mount in compile's mount table
  shows a directory beneath the covering scope mounted outside the scope;
- (g) without the row, the path's nearest row allows both a read and a modification (a write entry's answer, no
  `deny_read` or `deny_write` above it), so the name entry alone decides it, with the verdict and the rule the row gave.

Of the rows that qualify, compaction drops **only as many as needed**: in reverse canonical-path order, until the
keyed paths are `PlaneCompactAt` or none qualifies, so ordinary tables keep inode-following rows. The result is a pure
function of the table.

Compile records (d) to (f) in the RuleTable (`FSRule` gains the file kind, `nlink`, the casefold flag and a
file-mount-point flag, beside `IsMountPoint`, whose directory-only meaning is unchanged; `NameDenyRule` gains a
bind-exposed flag), so the row set is a pure function of the table (F8). The facts are gathered only on a host where
compile's reach (ADR 0019) includes a plane tier; kind and `nlink` come from the `Lstat` the scan already makes;
`FS_IOC_GETFLAGS` (a directory open and an ioctl) is made per directory only when the keyed count
exceeds `PlaneCompactAt`, and inside the scan's own budget (`envScanMaxTime`, I6: the agent chooses how many `.env`
files exist and where); a fact the budget left ungathered is unknown, and an unknown fact keeps the row. The
RuleTable keeps every entry: Landlock and the listener are untouched (I3). Compaction is therefore verdict- and
name-neutral by construction; `compile` and the `PlaneDiagnostic` text say when it applied and how many rows it
dropped.

What compaction is not: a defence. Files under a read-only parent ((g) fails) are never compacted and still cost
Landlock's enumeration descriptors; planted hard links (`nlink > 1`), symlinks and casefolded directories keep their
rows. An earlier run (or the agent's own tooling between runs) can plant tens of thousands of such files in the
project and so force `ErrPlaneCap` and, for an auto run, tier cgroup (E13, stated by doctor and the capability
line). On a host whose hard `RLIMIT_NOFILE` is 1024 (some containers) §2.4 condition 7 can refuse a table below the
threshold; the threshold is not read from the machine (F8), and such a table runs at tier cgroup as today.

### D7. Tiers

| | tier landlock | tier cgroup, fanotify fallback (listener and supervisor) | tier cgroup, `lsm`/`fmod_ret` plane | tier bpflsm |
|---|---|---|---|---|
| read of a covered file | expansion only | refused by the listener, by path, `read-denied` (C0's `(deleted)` fix required) | refused, `read-denied` | refused, `read-denied` |
| write-open of it (`O_WRONLY`, `O_RDWR`, `O_TRUNC`, `O_CREAT`, `O_TMPFILE` linked to it) | expansion only | refused by the supervisor before the syscall and by the listener, `read-denied` (as for a nested `deny_read`, F11) | refused, `write-outside-contract` | same |
| `mknod`, `symlink`, `link`'s new name, a rename onto it | expansion only | refused by the supervisor, best effort (R15c's race), the operation's reason | refused, the operation's reason | same |
| `unlink`, `truncate(2)` | expansion only | refused by the supervisor where it is notified, best effort, as for a nested `deny_read` today; `ftruncate` on a descriptor inherited from outside the run is not | refused | refused |
| link or rename from it; a directory leaving coverage (D5) | expansion only | refused by the supervisor (R15d), best effort, `rename-outside-contract` | refused, `rename-outside-contract` | same |
| `fs.deny_read.created_later` (run's capability line) | false | false | true when the conditions below hold | true when the conditions below hold |
| `compile --test` column | landlock: no name entries | cgroup (`Evaluate` at cgroup, the listener's and `AdvisoryFS`'s answers) | bpflsm column (the plane's rows, name rows and climb) | bpflsm column |

**The fallback.** The listener decides opens on the canonical path its event's descriptor reads back, with the core's
predicate (folded final component, scopes by path, dependency directories as path components, D3 by path). A path
read back with a trailing `" (deleted)"` is decided under **both** spellings, the raw one and the one with the suffix
stripped, and refused if either refuses (C0; F12). The listener marks each scope's mount and **every mount point
beneath each scope** for `FAN_OPEN_PERM` (enforce-cgroup-observe R8's rule for `deny_read` entries), refuses Prepare
with `ErrMountTable` when the mount table cannot be read and the policy has a scope, and treats a scope as something
it can refuse (`canRefuse`). Directory opens never reach it (no `FAN_ONDIR`). Every other mutation is the
supervisor's: `decide.AdvisoryFS`'s tier-cgroup branch asks the same `NameIndex` for write-opens, creations
(`mknod`, `symlink`, `link`), unlink, truncate and both ends of a rename, so the supervisor's enforced refusals
(`fallbackMutation`), `Evaluate` at cgroup and `compile --test`'s cgroup column agree, with the reasons above, and
the conformance baseline stays `[]`. Any divergence left after that is a new, documented baseline entry with its
reason. Supervisor R15d asks `FSIndex.NameMoveRefused` beside `DenyReadMoveTarget`.

**The capability** `fs.deny_read.created_later` is true for a run only when all hold: a plane mode decided the run;
its slot header carries `TEGO_SLOT_NAME_DECIDES`; every name-eligible entry of the table, the built-in pair
included, is in `NameDeny` (none left out by a cap or a collision); and every approval completion the run can reach
checks names (interface 2), or the run has no `fs.ask` entry and no gate that can hold an open whose scope overlaps
a name scope. Otherwise it is false (a run with `deny_read: []` has no name entry and reads false). The key is
written in every run's line (every row is written), and the run_start's `record_minor` moves to the next revision,
which says the row and D8's rule forms are known to the writer, so the key's absence reads
unambiguously as an older writer.

### D8. Rule naming

A name entry names only the decisions it changes (D1); where the walk refuses, the row's rule stands.

- A refusal of a covered file **that has an entry in the RuleTable at its canonical path** (the expansion's,
  compacted or not) is named by that entry: `fs.deny_read[<raw glob>]` for a declared glob, `fs.deny_read[<path>]`
  for the built-in. Uncompacted, the walk already refuses with that row; compacted, the name check refuses and the
  recorder, which names path hooks by path (§2.15), names the RuleTable's entry at that path. So compaction never
  renames a line.
- Any other refusal by a name entry (a file created after compile or past the scan's bounds, D5's directory rename,
  a sample whose path the recorder cannot resolve) is named by **the name entry's own rule name**: for a declared
  glob its `fs.deny_read[<raw glob>]`; for the built-in the label `fs.deny_read[<scope spelling>/**/.env]` or
  `fs.deny_read[<scope spelling>/**/.env.*]`, one per entry and scope, the scope being the deciding entry's nearest
  scope. `**` is not contract syntax, so a label can never equal a declared entry's name (ADR 0030's uniqueness).
- A REFER refusal of a covered source names the source by the same two rules.
- In the kernel a name decision's `rule_idx` is `TEGO_PLANE_RULE_NAME (0x8000) | scope << 6 | i`, `i` the entry's
  position in `PlaneRows.NameRules` (< 64), `scope` the bit index (< 8); fs rows stay below 4096, `0xffff` stays
  none, `TEGO_PLANE_RULE_FS_ROW` (bit 16) and `TEGO_PLANE_RULE_LISTEN` (bit 17) keep their meaning, and every
  reader checks the tag before reading `rule_idx` as a row.

These names are entries of the compiled table, printed by `compile`, so they are in the record contract only with
the record contract amended in the same commit: `spec/record/v1` (`rule` is "the declared entry, a built-in entry of
the compiled table (a path or a name-entry label), or `unmatched`"), record-ledger §2.2 (the label form), and
`drift.declare`, which declares every `NameDeny` rule name (a declared glob as a declared entry, even when it matched
nothing at compile; the built-in labels as auxiliary entries, as `BuiltIn` FS rules are), with a drift test.

### D9. ABI and build hash

- A pinned `HASH_OF_MAPS` **`tego_plane_name_rows`** by `run_idx`, inner `HASH`, `NO_PREALLOC`, **`max_entries` 65**:
  at most 64 name rows plus one **config row at key 0** (gen; the run's scope mask; the distinct entry masks D5
  iterates; the dependency names). Name row value `struct tego_plane_name_row {gen; flags (PREFIX); name_len;
  narms; arms[8] {mask, depth (0 any, 1 the parent), flags (EXEMPT), rule}; name[256]}`.
- **Key spaces**: 0 is the config row; a name key is a 64-bit FNV-1a pass over the folded, masked words and the
  length, with bit 63 cleared, bit 62 clear for an exact key and set for a prefix key, and a result of 0 replaced by 1.
  The key function lives in a leaf Go package compile can call (`agent.NameKey`), mirrored in C, held equal by a
  vector test. The key is a hash of name bytes, never a kernel address, so userspace may compute and write it (ADR
  0025 (1) governs address keys; enforce-plane §8 invariants 4 and 10 gain this carve-out, which bare exec names
  already need: final-name bytes are an input, a name key is computed in userspace and never trusted alone, a hit is
  confirmed by the bytes).
- **Collisions**: two literals or forms whose keys are equal in one table are found at compile's allocation (the
  later entry is left out, Terms); the fill writes every row with `BPF_NOEXIST`, so a collision compile missed fails
  Prepare (`ErrPlaneNameKey`) and never overwrites a deny row with another row or an exemption.
- **Fill order and failure**: Prepare (1) deletes every entry of the slot's name map (a previous run's rows share the
  slot until cleared, so the clear precedes the config-row write and `max_entries` needs no headroom); (2) writes the
  config row; (3) writes the name rows; (4) writes the slot header, flag set, last. An error at (1) to (3) aborts
  Prepare before the header is written. The clear paths (Detach, `purgeSlot`, the reaper, `tego_plane_clear`) clear
  the name map with the slot's other rows.
- **Fail closed in the kernel**: with `TEGO_SLOT_NAME_DECIDES` set, a lead-hit name whose slot has **no inner name
  map** at `run_idx`, or whose **config row is absent or of another gen**, is refused `path-unresolved`, counted
  `norows` and recorded as a fallback sample, as `tego_plane_walk` treats `NOROWS` (F17); it never reads as no match.
  A *name* row of another gen at a lead hit is absent (no match): Prepare writes every row of the run's gen before its
  header, so a run's own row is never missing while its header is live (a process able to delete pinned-map entries
  is root outside the run, out of scope as for fs rows).
- `tego_plane_row.pad` and `tego_plane_fill_row.pad` become `scope` (layout unchanged). No new fill kind (F7).
- Slot flag `TEGO_SLOT_NAME_DECIDES = 0x80`. The slot header (`struct tego_plane_slot`) grows
  from 16 to **128 bytes**, laid out so the common path stays on its first cache line: bytes 0-63 hold the four
  existing words, the lead count, the prefix-length count, the eight lead lengths, the four prefix lengths and lead
  words 0 to 3; bytes 64-127 hold lead words 4 to 7 and the minimum name length, read only when more than four leads
  exist. The built-in pair needs one lead (`.env`, folded, length 4, covering both its forms). The slots `ARRAY`
  grows from 64 KiB to 512 KiB over 4,096 slots. What is read only after a hit lives in the config row.
- Constants `TEGO_PLANE_NAME_ROWS_MAX 64`, `TEGO_PLANE_NAME_KEYS 65`, `TEGO_PLANE_NAME_ARMS 8`,
  `TEGO_PLANE_SCOPES_MAX 8`, `TEGO_PLANE_NAME_LEADS 8`, `TEGO_PLANE_NAME_PREFIXES 4`, `TEGO_PLANE_RULE_NAME
  0x8000`, each mirrored in Go and held equal by `TestPlaneCapsMatchRowCompiler`.
- Every plane object (rd, pr) and the fill change, so **the build hash changes**: a binary never adopts another
  build's pinned plane (another directory), and R20's rule (a pinned program is adopted only when every map it reads
  is this mode's pinned instance) covers the new map. Runs of the old build and the new one coexist, each on its own
  pins.
- **Doctor**: the plane probe's known answers gain name cells (R21); **a mode whose name cells fail is not selected**,
  deliberately: the plane keeps one row set per table (F8), a kernel that answers a name cell wrongly runs plane
  objects whose name code we do not trust, and the name programs's gate already requires every MATRIX row to pass. Doctor
  names the failing cell, so the degrade is stated (I7). The probe cache is per build.

### D10. The built-in's scope

**Scoped**: beneath the contract file's directory and the run's working directory, as the scan is rooted (P7's
default). The machinery takes a scope set per entry, so the unscoped reading (scope `/`) is a compile-time change of
the built-in's scopes; open question 1 is below.

### Proposals and what this ADR decides

| Proposal | Decision |
|---|---|
| Full deny entry, create included | D1, confirmed; directories and metadata excluded; decides only what the walk allows |
| Final component, ASCII fold, exact or literal prefix | D2, confirmed; masked lead prefilter; mount roots use the mountpoint's name; literal floor |
| Only a declared write at exactly that path | D3, confirmed by resolved place and folded name, top-level contract only; cancels every entry's arms for the name |
| Scope bits plus a second walk after a match | D4, confirmed; dependency exclusion (exact names, mountpoint names); early termination |
| Directory move-out refused | D5, widened: also into a dependency directory or to its name; exchange both ways; moves into coverage allowed, residual stated |
| Alias-safe compaction above 1024 | D6, confirmed; adds (e) one spelling, (f) no bind exposure and no file mount point, (g) parent allows both, drop only as needed |
| Plane modes plus listener opens | D7, confirmed and corrected: the fallback's supervisor refuses mutations (F11); capability conditional |
| Deny_write rule under PROTECTED, tagged name rule | D8: the walk's rule where it refuses; RuleTable entries by path; otherwise the name entry's own rule, record contract amended |
| New build hash; adoption needs the map | D9, confirmed; 65 entries, key spaces, NOEXIST, fail-closed lookups |
| The built-in scoped | D10, default taken; open question 1 below |

## Why

1. **D1, a whole entry.** [documented] It is ADR 0039's decision 2 and the meaning the root model already gives a
   `deny_read` entry (F4), so the plane, `Evaluate`, the listener and the supervisor need no notion of whether the
   file existed, and dropping a covered row (D6) changes no verdict. A write-only `.env` would be useless inside the
   run (nothing in it may read it back), and refusing the agent's direct rewrite or creation of one keeps it from
   editing the user's environment file in place. That is a narrower claim than "the agent cannot change what the
   user's tools read as `.env`" (D1's last paragraph, Residuals). Directories are excluded because the scan never
   matched one (F2) and a final-component deny of a directory protects nothing beneath it while breaking
   `python -m venv .env`.
2. **"Only what the walk allows".** It keeps every refusal the plane makes today, with its rule, and skips the name
   pass on every refused action; with D6's (g) it is what makes compaction name-neutral.
3. **D2.** Folding closes ADR 0039's own casefold condition for ASCII spellings at a few ALU operations a word, with no
   compile-time detection to get wrong. A prefix form is required by the built-in's real pattern (F2). Suffix forms
   would put a tail read and compare on every open and no built-in needs one. The masked lead prefilter keeps the cost
   of the many opens that match nothing at one word read and a few compares, and is correct for short inline names.
   The mountpoint's name at a mount root is the path's component, which is what `Evaluate` and the listener read.
4. **D3.** It mirrors "a declared path beats a glob's expansion" and R20's built-in `deny_write` drop, makes ADR
   0039's stated way out true (F5), and survives atomic saves because it names a place, not an inode. Limiting it to
   the top-level file keeps a profile from silently removing a built-in protection (R5's spirit).
5. **D4.** The walk cannot be asked (F1). A climb only after a match keeps the cost off every other open; it reads the
   current tree, so a directory moved in during the run is judged where it now is; it is the only place the
   dependency-directory rule (F3) can be applied to directories created during the run; and a scope row is an ordinary
   complete row (pinned by the domain, gen- and identity-checked), so no new fill kind (F7) is needed. Coverage at
   any depth is the sound over-approximation: coverage by depth is not stable under directory renames.
6. **D5.** Without it `mv sub /tmp/x; cat /tmp/x/.env.local` (or `mv app node_modules`) defeats created-later
   protection with one command, and also compaction's dropped rows. A file rename is already refused by D1.
7. **D6.** The built-in scan can list 50,000 files; rows per file meet `EMFILE` near 3,800 keyed paths and the
   4,096-row map (enforce-plane §2.4 condition 7), and such a project now falls to the listener, whose opens cost
   85 µs at 2 runs. The predicate drops only rows whose files the name entry provably decides alike, by every way the
   run can reach them; the constant keeps the recorder's rows equal to Prepare's (F8); dropping only as many as needed
   keeps inode-following rows where they fit.
8. **D7.** The bodies are shared (F6); the fallback already converges on the plane's semantics through the listener
   and the supervisor (F11, ADR 0021 (5)), so the name index is one more question the same functions ask. The
   capability line can only say true or false (F9), so it says true only where every piece is there.
9. **D8.** The ledger names what `compile --test` names (R24, R25) and what the compiled table holds; naming a covered
   file by its expansion entry keeps today's names and makes compaction invisible in the ledger; a label for the
   rest names the mechanism's actual reason (ADR 0016) and is traceable to the table (ADR 0030).
10. **D9.** A separate map keeps exec rows byte-exact and their cap their own (F10); a new hash keeps an old pinned
    plane from ever being taken as name-capable; fail-closed lookups keep "a missing row never reads as a permission"
    (enforce-plane R6) true for the new map.

## Consequences

### What users see

1. At tiers cgroup (plane modes) and bpflsm, a `.env*` file that a tool outside the run **creates directly at a
   covered path** (by that name, in a real directory beneath the project's scopes, outside dependency directories)
   while the run is live is unreadable to the agent: the purpose. The Residuals list what this does not cover: a file
   written through a temporary name (readable at that name until the rename, and through a descriptor the agent
   already holds on it), a path whose directory the agent replaced with a symlink, a casefolded or dependency-named
   directory, and other spellings.
2. At those tiers the agent cannot create a file at a covered name, nor overwrite, truncate, delete or rename an
   existing covered file, unless the top-level contract names that file in `fs.write` (and it exists before the run).
   This protects content and name, not metadata (chmod, chown and xattrs stay allowed), and not a `.env*` that comes
   to sit at a path because the agent moved a directory into coverage.
3. **What breaks** (open question 2): tools that create, copy or delete `.env*` files without reading them fail with
   `EACCES` partway through:
   - `git checkout`, `switch`, `pull`, `rebase`, `stash pop`, `worktree add` and `clone` when the revision adds or
     changes a tracked `.env.development`, `.env.production` or `.env.test` (Create React App, Vite and Next commit
     these; files present at compile are already immutable at these tiers by F4, new ones arrive mid-run);
   - `rm -rf` and `git clean -fdx` over a tree holding a covered file created during the run;
   - `cp -r` of a template, `prisma init`, `vercel env pull`, build steps copying `.env*` into an output directory,
     an agent scaffolding `.env.local`, tests writing `.env.test`.
   `compile` prints this per tier, with the way out: create the file before the run and name it in `fs.write` (one
   file at a time), and `compile --test` gains rows for a checkout-created and a copied `.env.development`.
4. At those tiers a directory cannot be moved out of the project, into a dependency directory or to one's name (`mv
   build /tmp/` fails with `EACCES`; `cp -r` and `rm -rf` of files no entry covers work), for every contract that has
   the built-in list.
5. Existing `.env` files deeper than the scan's six levels, or past its 50,000-entry or 2 s bound, are covered at the
   plane tiers (and at the fallback), where today only an `[unenforced]` warning stands; tier landlock is unchanged
   and keeps the warning.
6. `.ENV` and `.Env.Local` are covered at those tiers too.
7. **A compatibility change for declared globs** (open question 5): at tiers 2 and 3 a declared `<dir>/<literal>` or
   `<dir>/<literal>*` final component now covers that name or prefix **at any depth** beneath the glob's literal base,
   outside dependency directories, including files created later: `./config/key*` also covers
   `./config/a/b/keyboard.json`; `./*/secret.json` also covers `./secret.json` and `./a/b/secret.json`. Deny side
   only; `compile` prints the widening per entry and tier. A literal shorter than the floor (2 bytes exact, 3 bytes
   prefix) keeps today's expansion.
8. A project whose keyed paths pass 1,024, most of them `.env` files under its write entry, keeps tier bpflsm.
9. `fs.write` in the top-level contract naming an existing built-in `.env` compiles (dropping it from the built-in
   list, with a warning) where it was an error; from a profile it stays an error.
10. The capability matrix gains a last row, `fs.deny_read.created_later` (21 rows), and `run_start.capabilities` a
    key, with the next `record_minor`. The record's `rule` gains the built-in name-entry label form (D8). Reasons stay
    in the closed set and D5 reuses `plane_reason: refer`.
11. On a landlock-only host (compile's reach has no plane tier), `compile` prints nothing new and makes no new
    syscalls.

### What it costs

- Every decided open, create, unlink, truncate, link and rename in a run with name entries (any run with the built-in
  list): the prefilter, one masked word read and at most eight compares, on the header's first cache line. Target
  ≤ +30 ns p50, limit ≤ +100 ns. On the probe-read build (AL2023 6.1) the word read is a `bpf_probe_read_kernel`
  call, so the target will likely print `TARGET-MISS` there; figures are attributed per build.
- A candidate (lead matched): the folded key pass, at most five lookups and compares, and for a match the climb,
  which stops at the nearest deciding scope.
- A directory rename in such a run: two climbs.
- Prepare: the name-map clear, at most 65 userspace map writes and at most 8 scope rows (budget ≤ +5 ms). A fourth
  `HASH_OF_MAPS` outer adds one RCU grace period (7.6 to 11.5 ms, R6, ADR 0026) to each slot's first Prepare per
  build, outside that budget, measured in its own row.
- The plane objects: two more global functions (the name check, the climb) and their `bpf_loop` callbacks, verified
  in every program that calls them, on every MATRIX row; cold start's `load.plane` and `probe.programs` grow
  (to be re-measured, with a per-program verified-instruction delta table per row). A refusal on one row drops that
  row's whole plane to the listener.
- The slots `ARRAY` grows from 64 KiB to 512 KiB.
- **On the fallback**, every run with the built-in list now marks the project's mount, and every mount point beneath
  each scope, for `FAN_OPEN_PERM`, even with no `.env` present: today only mounts holding a `deny_read` entry are
  marked (`markMasks`). Every host process's opens there then pay the listener round trip (85 µs at 2 runs, 1.3 ms at
  8, enforce-plane §10.1; enforce-cgroup-observe E34). Doctor's fallback clause says so; C10 measures it with the project on its own mount.

### Residuals, stated plainly

- **Outside processes.** A process outside the run that renames or links a covered file to a name or place no entry
  covers lets the agent read it. A file that keeps its row is still caught by the inode row; a file created during the
  run, or one compaction dropped, is not.
- **An outside tool's atomic save through an uncovered temporary name** (`tmpXXXX`, then a rename to `.env`): the
  content is readable at the temporary name until the rename, and a descriptor the agent opened on that temporary
  file keeps reading the file after the rename. Coverage is decided at open time, by the object's name and place.
- **Agent-shaped layout at a path an outside tool will write to.** The agent can remove an empty directory and put a
  symlink in its place (`ln -s /tmp/x config`), create a directory and make it casefolded while empty (`chattr +F`;
  non-ASCII spellings), or create a dependency-named directory on the tool's path. Symlinks and directories are never
  decided by D1 and D5 does not apply to them, so the tool's `config/.env` lands where no entry covers it. Likewise a
  `.env` symlink an outside tool makes: opens follow it, and its target's own name and place decide.
- **Directories moved into coverage** (D5 allows them): `mkdir -p node_modules/s && echo X > node_modules/s/.env;
  mv app app.old; mv node_modules/s app` leaves agent content at `app/.env`. D1 protects an existing file's content
  and name and the agent's direct creations, not a `.env*` that appears at a path through a directory move or swap.
  The agent has other ways to change what the user's tools run (`.envrc`, `package.json` scripts) that no name entry
  covers either.
- **Other spellings of one file**: a casefolded directory's non-ASCII equivalents (Unicode default-ignorable code
  points on kernels before the 2025 casefold fix), vfat and msdos 8.3 aliases, ntfs3 DOS names, case-insensitive CIFS,
  9p or FUSE filesystems. `compile` warns when a scope lies on such a filesystem or in a casefolded directory; D6
  keeps every row there. Folding also denies an ASCII case variant the author did not name (deny side only), and D3's
  exemption covers the entry's case variants in its directory (allow side, the author's own file).
- **Bind mounts**: a directory beneath a scope mounted outside it reaches files without passing the scope (SEMANTICS
  §2's rule for an ancestor's entry). D6 keeps the rows under any such bind compile sees, and of any file mount point;
  one made during the run (by root outside the run; a landlocked agent cannot mount) is the residual.
- **A scope directory removed and re-created** during the run is a new directory with no scope row. The agent needs
  its parent writable and no covered file inside (D1 refuses deleting one), and a nested built-in scope is dropped in
  favour of its parent anyway.
- **Prediction drift after renames**: the plane follows inodes (scope rows, D3's exempt parent), `Evaluate` follows
  the compile-time paths; after an allowed rename `compile --test` can predict a refusal the kernel does not make
  (`mv app app2`, then `app2/.env` exempt). The same holds for every inode-keyed row today.
- **The fallback**: the supervisor's refusals of mutations and moves are best effort against the races R15c states;
  `ftruncate` on a descriptor inherited from outside the run is not refused; the capability line says false.
- **Dependency directories**: a secret kept inside `vendor/` or `target/` is covered by no name entry, as the scan
  covers none there today.
- **Paths more than 64 levels below their nearest scope**: a name-matched file whose climb cannot decide its arms
  within the bound is refused `path-unresolved` (fail closed, counted); `Evaluate` answers the same.
- **A planted tree** can force `ErrPlaneCap` and, for an auto run, tier cgroup (D6's last paragraph).
- **Approved asks**: until interface 2 lands, an approval completes outside the plane (F13); D7 keeps the capability
  false for any run that can reach one over a name scope.
- **The fmod_ret mode** skips other LSMs on a refusal (enforce-plane §9); that now applies to name refusals too.

## Rejected options

- **D1**: *reads and REFER only* (ADR 0039's Consequence) makes compaction turn refused writes of existing files into
  allowed ones (F4), needs a create-versus-overwrite distinction the path model does not have, and leaves write-only
  files and unreviewed rewrites; its cost is in open question 2. *Match directories too*:
  protects nothing beneath them and breaks virtualenvs named `.env` (F2). *The name entry names every decision as a
  virtual depth-0 entry*: renames today's refusals at the plane tiers and makes compaction rename ledger lines unless
  `Evaluate` changes as well. *Decide metadata (chmod) too*: R12 keeps attribute hooks for `deny_write` targets, and
  the expansion's entry does not decide them today, so compaction would change verdicts.
- **D2**: *exact names only* (accepted text) misses `.env.local` (F2). *Suffix and class forms*: an every-open tail
  read for no built-in need. *No folding*: leaves the ASCII casefold spellings ADR 0039 named. *Full Unicode folding
  in BPF*: tables, a per-kernel definition, and no gain for `.env`. *A length bitmask prefilter*: any name
  as long as a prefix passes it, so with the built-in's `.env.` almost every name would take the lookups. *The mount
  root's own `d_name`*: misses a file bind-mounted over `.env` while compile says it is covered.
- **D3**: *ancestor write entries reopen*: every project's `.env` lies under its write entry. *Keep the
  contradiction*: no per-file way out, against ADR 0039's own text (F5). *A row-kind bit on the write entry's inode*:
  lost on an atomic save or a delete and re-create. *Drop through any file in the `extends` chain*: a profile could
  silently remove a built-in protection. *An exemption that cancels only the arms of the row it sits on*: leaves
  `.env.test` refused by the built-in prefix row, so the stated way out fails for every `.env.*`.
- **D4**: *up to four scope inodes compared with the walk's visited inodes* (accepted text): impossible (F1). *Inherited
  scope bits on every row, no climb*: cheaper, but stale when a directory holding rows moves into or out of a scope
  during the run, and the dependency-directory rule needs a climb that reads names anyway. *Name checks at every step
  of the main walk*: ADR 0039 rejected it for cost and it is still rejected. *No dependency exclusion*: refuses
  package installs and removals at the plane tiers (F3). *Climb to the root*: one exemption made
  every covered open climb to `/`, and a deep project met BOUND below its own scope. *Exact-depth arms* (a declared
  `./*/secret.json` covering one level only): coverage by depth is not stable under directory renames, so D5 would
  have to refuse every move that changes a depth. *Fold dependency names*: the scan compares exactly, so a `Vendor/`
  directory would be scanned (its files get rows) but excluded from created-later coverage.
- **D5**: *no rule, the bypass stated as a residual*: one `mv` defeats the feature. *Refuse every directory rename in a
  run with name entries*: refuses ordinary refactors. *Refuse moves into coverage too*: it
  closes the directory-swap path to planting a `.env` (Residuals), but refuses the build-in-a-temporary-directory then
  move-into-place pattern and `mv node_modules node_modules.bak`, in every contract with the built-in list, for an
  integrity gain the agent can get elsewhere (`.envrc`, `package.json` scripts). The purpose is reads; the residual
  is stated.
- **D6**: *no compaction*: such projects stay on the listener. *Always compact*: loses inode-following rows for every
  project. *A threshold read from the machine (`RLIMIT_NOFILE`)*: makes `CompilePlane` impure, so the recorder's rows
  would differ from Prepare's and lines would be misnamed (F8). *Drop every name-matched row*: changes verdicts (hard
  links, casefold spellings, binds, file mount points) or names (a refusing parent). *Drop every qualifying row once
  over the threshold*: needlessly gives up inode-following for tables just over 1024.
- **D7**: *tier bpflsm only* (accepted text): F6. *Tier landlock*: Landlock cannot express names, and its domain
  cannot change after `landlock_restrict_self`. *State create, unlink and truncate as not refused at the fallback*, or
  rename-onto: false; the supervisor refuses
  them as it does for a nested `deny_read` (F11), and leaving `AdvisoryFS` without the name index would make the
  fallback the one place that diverges. *The listener refuses every run opener's unlinked object* (an alternative for
  F12): refuses tools that open an unlinked temporary file through `/proc/self/fd`, where deciding the stripped
  spelling refuses only what the original name would have. *Select a mode whose name cells fail with the flag clear*:
  needs a second row set per table (compaction depends on name entries) that the recorder must also know, or a
  silent loss of compaction; rejected for D9's reason.
- **D8**: *name a file created later by a constructed path* `fs.deny_read[<path>]`: an entry in no
  RuleTable or compile output (ADR 0030, ADR 0016). *Name a D5 refusal by the REFER convention* (the source's nearest
  entry, typically the enclosing `fs.write`): names an entry that allows the move as the reason it was refused.
  *Unmatched with a gap for an unresolved directory*: the kernel said which name entry decided; dropping that is
  less honest than the label.
- **D9**: *name rows in the exec map* under a key bit: couples exec and fs decisions, shares the 1,024-row cap, and the
  exec compare must stay byte-exact. *A fourth fill kind*: F7. *Refuse the whole table on a key collision*: any
  profile literal could then take the plane from a run; leaving the later entry out costs only that entry. *63 name
  rows*: the clear-before-write order makes 65 entries enough.
- **D10**: see open question 1; the mechanism supports both.

## Attacks considered, 2026-10-05

- *`mv sub /tmp/x` then read `/tmp/x/.env.local`.* D5 refuses the move at the plane tiers; R15d refuses it best effort
  at the fallback.
- *`mv app node_modules`, or `mkdir node_modules; mv app node_modules/`, to put covered files beneath a dependency
  directory.* D5 judges the new place and the new name.
- *A tmpfs or volume mounted at `node_modules`, or a file bind-mounted over `.env`.* D2 and D4 read the mountpoint's
  name, so the kernel and the model agree; D6 (f) keeps the row of a file mount point.
- *`ln .env.local x`; `mv .env.local x`; `renameat2(x, .env.local, RENAME_EXCHANGE)`.* D1: the source has
  strictness 2; a rename or exchange of a covered file is a modification at both ends; a link's new covered name is a
  creation.
- *`O_TMPFILE` then `linkat(…, ".env")`.* The new name is a creation of a covered file.
- *Open through `/proc/self/fd/N`, `/proc/<pid>/root/…`, a symlink, `openat2`, or io_uring.* The same dentry reaches
  `file_open`; its own name and the climb from it decide.
- *Block an open in `FAN_OPEN_PERM` and unlink or rename over the file meanwhile.* The agent's unlink is refused by
  the supervisor; an outside rename-over leaves `/p/.env (deleted)`, which C0 decides under `/p/.env`.
- *Rename a long-named file to `.env` from outside, so the inline name keeps stale bytes.* The pass masks past
  `d_name.len`.
- *A concurrent rename of an ancestor during the unlocked climb.* A rename the plane allows keeps coverage (D5), so the
  climb sees a covered chain before, after or mixed: it may refuse spuriously, never admit (enforce-plane §7's
  argument).
- *Make the climb fail, delete the config row, or run with no name map.* Each refuses (D9), counted.
- *Two runs, one slot reused.* Prepare clears the name map before writing; name rows and the config row carry gen;
  Detach, purge and the reaper clear them with the slot's other rows.
- *A key collision planted through a declared literal.* Compile leaves the later entry out; `BPF_NOEXIST` keeps any
  missed collision from overwriting; a hit is confirmed by the folded bytes.
- *A name longer than a word, or 255 bytes.* The pass covers 32 words; the prefilter reads one.
- *The prefilter on hot paths.* One word read; `ripgrep` reading `.gitignore` in every directory fails the `.env` lead
  at its second byte.
- *A recycled scope pointer.* A scope row is an fs row: identity-checked on every climb hit (R6), pinned by the domain
  (ADR 0025 (3)).
- *Compaction hides a hard link made before the run.* (d) keeps every row with `st_nlink > 1`.
- *Compaction and a casefolded or vfat project.* (e) keeps those rows; `compile` warns about the scope.
- *A profile (`extends`) naming `./.env` in `fs.write` to drop it from the built-in list.* Refused: D3's drop needs the
  top-level contract file.
- *Ask a human to approve `.env.local`, or rename a file to `.env.local` during the wait.* Interface 2 refuses a
  covered path without a prompt and re-checks after the wait; until then the capability is false.
- *Prediction drift.* `Evaluate`, `PlaneRows`, the listener, `AdvisoryFS` and the supervisor ask one
  `decide.NameIndex` (ADR 0028); `TestPlaneRowsMatchEvaluate`, `TestPlaneEvaluatorMatchesEvaluate` and the
  `AdvisoryFS` parity tests hold them together, names and reasons included, over generated tables with name dimensions,
  and the guest differential (C10) holds the kernel to the model.

## Implementation plan

### Commits

**C0. Listener: unlinked files (`enforce/cgroup` `fanotify.go`, `policy.go`; `decide` `cgroup.go`).** A path read
back with a trailing `" (deleted)"` is decided under the raw and the stripped spelling, refused if either refuses, for
`decideOpen` and `decideExec`; the same in `decide.ListenerOpenRefused` so `AdvisoryFS` agrees. Filed as a defect of
enforce-cgroup-observe (file-level `deny_read` entries, the `.env` expansion included) with a dated Changes entry.
Tests: `TestListenerDecidesTheUnlinkedSpelling` (raw, stripped, a real name ending in ` (deleted)`), root
`fanotify_*_integration_test.go`: a helper renames over `.env` while the run's open waits in `FAN_OPEN_PERM` (a
test-hook delay); refused.

**C1. Docs.** This ADR as `docs/adr/0043-name-entries-for-deny-read.md`; ADR 0039 gets `Amended by 0043`; `docs/adr/README.md` index (new row; 0039's "Later changes");
SEMANTICS §2's 2026-09-30 note points here (decided, not built); enforce-plane gains a §2.20 placeholder "Name entries
(ADR 0043): not built" with the acceptance list below; agent-contract R6 notes D3 and D10 as decided. Tests:
`tools/rulecheck`, the doc lint.

**C2. Compiler (`pkg/spec/agent`).** `NameDenyRule{Literal, Prefix, Scopes []NameScope{Canonical, Spelling},
Except []string, Raw, Pos, BuiltIn, BindExposed}`, `RuleName()` (D8) and `RuleTable.NameDeny`; `agent.NameKey` (D9);
`declared` classifies a whole deny_read glob's final component with the literal floor (`compile_fs.go:452-498`);
`builtIn` adds the exact and prefix entries and shares one `EnvSkipDirs` list (exact compare) and one exceptions list
with `envFiles`/`isEnvFile`; scope minimization; allocation in Terms' order with collision detection; D3's built-in
drop in `unenforced` (`:634-641`) for top-level write entries only (by `Pos`'s source file), with a warning, and the
"created as a directory" note; the `fs.ask`-names-a-covered-file warning; D6's facts (kind and `nlink` from the scan's
`Lstat`; the file-mount-point flag from `mountTable.lookup`; `FS_IOC_GETFLAGS` only past `PlaneCompactAt`, inside
`envScanMaxTime`); every new line and fact-gathering gated on the reach (`mayLand` of a plane tier, `.only(tier)`);
`print.go` prints each entry, its scopes, its tiers, the widening of a declared glob, D1's breakage list and D5.
Tests (`compile_namedeny_test.go`): `TestNameDenyClassification` (exact, prefix, `*.pem`, `a?c`, `[x]`, bare `*`,
`k*` under the floor, `**` refused, cut glob), `TestBuiltInNameEntries` (pair, exceptions, scopes, nested scope
dropped, cwd inside a dependency directory kept), `FuzzEnvNameRuleMatchesScan`, `TestNameDenyZeroMatchGlob`,
`TestWriteEntryDropsBuiltInEnv` (top level), `TestProfileWriteEntryKeepsTheContradiction`, declared `deny_read` plus
write still a contradiction, `TestMissingWriteEntryMatchingANameWarns`, `TestAskEntryNamingACoveredFileWarns`,
`TestNameDenyCaps` (allocation order: eight exempt `.env` files leave the built-in in, a declared entry out),
`TestNameDenyKeyCollisionLeavesTheLaterEntryOut`, `TestNameDenyScopeOnAliasingFilesystemWarns` (fake statfs and
ioctl), `TestCompactionFactsRecorded` (file mount point included), `TestCompactionFactsBoundedByTheScanBudget`,
`TestLandlockOnlyReachPrintsNothingNew` (and makes no ioctl), `TestDependencyNamesCompareExactly`,
`TestContractHashIgnoresNameDeny`.

**C3. Decision core (`internal/policy/decide`).** `NameIndex` built once per table (folded exact map, prefix list,
exceptions, scopes with spellings, D3 exemptions by resolved parent and folded name, dependency names),
`Match(path string, dir bool) (entry, scope int, ok bool)`; `agent.Action.Dir`; `Evaluator.root` at cgroup and bpflsm
applies D1 only where its own answer allows, and Evaluate's cgroup `FSWrite` loop answers `read-denied` for a covered
write-open as it does for a nested `deny_read`; Evaluate's rename applies D5 at cgroup and bpflsm;
`ListenerOpen`/`ListenerOpenRefused` take the index; **`AdvisoryList` carries the index and `AdvisoryFS`'s
tier-cgroup branch asks it** for write-opens, creations, unlink, truncate and both rename ends (tier landlock never
asks); `FSIndex.NameMoveRefused(src, dst string, dir bool) (rule string, refused bool)` for supervisor R15d;
`NameRefused(path string, read, modify bool) (rule string, reason record.Reason, refused bool)` for interface 2; a
`NameDecider` beside `FSDecider` for tier 2's recorder inference; `testtable.go` rows accept `dir: true`, and
`RunResolved` sets it from `Lstat` when the path exists. Tests: `TestEvaluateNameEntries` (each case at landlock,
cgroup, bpflsm), `TestNameEntryDecidesOnlyWhatTheWalkAllows`, `TestNameEntryExemptByDeclaredWrite` (after a delete
and re-create; `.env.test` exempt from the prefix row; a symlinked write entry exempts its target),
`TestAskEntryNeverExempts`, `TestNameEntryOutsideScope`, `TestNameEntryDependencyDirectories`,
`TestNameEntryFolding`, `TestNameEntryNeverDecidesADirectory`, `TestRenameDirectoryCoverage` (out, within, into, the
scope itself, into and to a dependency name, exchange both ways), `TestNameEntriesMonotonic` (property over
`genPlaneTables`: no name entry turns a refusal into an allow), `TestLandlockColumnIgnoresNameEntries`,
*TestAdvisoryFSAtLandlockIgnoresNameEntries*, *TestListenerOpenNameMatchesEvaluate* (and
`TestListenerOpenMatchesTheTableWalk` with name tables), *TestAdvisoryFSNameMatchesEvaluateAtCgroup*,
*TestNameMoveRefusedMatchesEvaluate*, `TestNameRefusalNamesAsD8` (expansion entry by path, label otherwise, a
symlinked scope spelling included). Benchmarks: `BenchmarkEvaluateName` < 1 µs and 0 allocs;
`BenchmarkIndexedEvaluator` unchanged (< 1 µs, 0 allocs).

**C4. Row compiler (`planerows.go`, `planeeval.go`, `rootrows.go`).** Scope rows with `PlaneRow.Scope`;
`PlaneRows.NameRows` (rows with arms, exemption-only rows), `NameRules`, `Scopes`, `Leads`, `PrefixLens`, the config,
`Compacted`; the tag with the scope bits; `Decide` and `KindAt` answer as the kernel (the walk, then the name check and
the climb with its termination simulated on the canonical path) with the object's directory flag;
`ScopeMoveRefused`; `PlaneEvaluator`'s rename passes `Dir`; D6 with `PlaneCompactAt` as a package variable and
drop-as-needed; `PlaneDiagnostic` names compaction; `RootIndex` takes the name index so `RootRows` stays projectable.
Tests: `genPlaneTables` gains name dimensions (none; built-in pair; declared exact; declared prefix; exempt write;
nested write below a scope; scope above a deny_write target; a dependency directory; two scopes) and `planeProbes`
gains `.env`, `.ENV`, `.env.local`, `.env.example`, `.env.test` exempt, a directory named `.env`, depth 63 and 65 below
the scope, a 40-level project with a file 30 below, outside every scope, beneath `node_modules`;
`TestPlaneRowsMatchEvaluate` and `TestPlaneEvaluatorMatchesEvaluate` pass with names and reasons equal on every probe
and rename pair; `TestPlaneCompactionIsVerdictNeutral` and `TestPlaneCompactionIsNameNeutral` (with
`PlaneCompactAt` lowered on generated small tables); `TestPlaneCompactionDropsOnlyAsNeeded`;
`TestPlaneCompactionKeepsAliases` (nlink 2, symlink, casefold directory, bind-exposed scope, file mount point,
read-only parent, `deny_read` parent each keep their row); `TestPlaneCompactionIsDeterministic`;
`TestRecorderCompilesTheSameRows`; `TestPlaneNameRuleTagDisjoint`; `planerows_scale_test.go`: 4,500 `.env` files under
a write entry fit after compaction and every one is refused; `TestPlaneQueriesAllocateNothing` with names.
Benchmarks: `BenchmarkPlaneDecideName` 0 allocs; `BenchmarkCompilePlaneCompaction` (4,500 `.env`) at most 1.5x
`BenchmarkCompilePlaneScale` at 4,096 rows.

**C5. ABI (`bpf/include/events.h`, `maps.h`; `internal/bpf`).** D9's map (65 entries), structs, key spaces, flag,
constants, the 128-byte header and the `scope` bytes; Go mirrors (`MapPlaneNameRows` in `PlaneMaps`, `PlaneNameRow`
via bpf2go `-type`, the key function's C twin with an SWAR fold); `gen.go` types and BTF anchors; regenerate the rd
and pr plane objects, the fill objects, the test fill and `adoption_specs_gen.go` (`test/vm/fetch-clang.sh`). Tests:
`TestPlaneCapsMatchRowCompiler` (caps, 65 keys, tag, slot flag), `TestPlaneLayoutParity` (slot header with its
first-line fields, name row, config row), `TestPlaneFillLayoutParity` (the scope byte), *TestPlaneNameKeyVectors* (Go
against a C table compiled into `bpf/testonly`, little- and big-endian, key 0 never produced, bit 62 per form),
`TestEveryUnpinnedMapIsKernelOnly`, `TestNoInodeKeyedKernelMap`, the adoption golden.

**C6. Kernel (`plane_name.h`, `decide.bpf.c`, `decide_stepb.h`).** A folded, masked pass and compare beside the exec
functions, which stay byte-exact (*TestExecNamePassIsUnchanged* compares their source); `tego_plane_name_check` and
`tego_plane_climb` as global `noinline` functions outside the walk markers, over laundered scalars, each `bpf_loop`
callback seeded from caller memory; the mount-root name rule; the fail-closed lookups (no inner map, config row absent
or of another gen: `path-unresolved`, `norows`, fallback sample); called after the walk allows, from `file_open`
(read and modify, non-directory), `path_mknod`, `path_symlink`, `path_link` (new name; source strictness),
`path_rename` (both ends; D5 for directories, climbs from `old_dir` and `new_dir`), `path_unlink`, `path_truncate`,
`file_truncate` (through `tego_modify_hook`, given the object's kind); never from `path_mkdir`, `path_rmdir`,
`bprm_check`, step C, the attribute hooks or the socket hooks; `file_open` keeps the slot header pointer it now
discards. Source tests (`bpf/tests`): *TestNameCheckIsGatedByTheHeaderFlag*, *TestNameCheckCallersAreTheListedHooks*,
*TestNameCheckRunsOnlyWhereTheWalkAllows*, *TestNameLookupsFailClosed* (every map lookup's NULL arm refuses and counts),
*TestNamePassMasksPastLen*, *TestPlaneClimbIsOutsideTheWalk*, `TestPlaneWalkHasNoStringOps` unchanged,
`TestPlaneReturnsOnlyZeroOrEACCES` unchanged, `TestBPFLoopCallbackStateIsSeededFromMemory` over the new callbacks.
Root load (`TestPlaneLoadsAndAttaches`, `-tags integration,tegobpf`): both builds, both modes, every MATRIX row,
verified instructions per program ≤ 20,000 and recorded with their delta per program and row in §2.20, ≤ 6 ms load
per lsm program on 6.17.

**C7. Backend (`internal/runtime/enforce/cgroup` `plane.go`, `planefill.go`, `planerun.go`, `pins.go`).**
`makeSlotMaps` adds the name inner map; adoption and `openPinnedPlanes` require it; `fill` writes the scope bytes in
the fs templates; after `putNameRows`, D9's fill order (clear, config row, name rows with `BPF_NOEXIST`), aborting
Prepare before the header on any error; `slotHeader` sets the flag, leads and prefix lengths and is still written
last; every clear path clears name rows; the run's capability set gains `CapReadDenyCreatedLater` only under D7's
conditions. Root tests: *TestPlaneNameRowsFillAndClear* (gen, header last, stale gen cleared, slot reuse),
*TestPlaneNameFillErrorAbortsBeforeTheHeader*, *TestPlaneNameMapAdoption* (a missing pinned name map adopts nothing),
*TestPlaneScopeRowsFilled*, *TestCapabilityFalseWhenANameEntryIsLeftOut*.

**C8. Recorder, listener, supervisor, record contract.** `observe/plane.go` `planeFS` resolves the tag before rows
(read, modify, REFER, D5, fallback sample: D8's names; one line per action); the listener's `decideOpen` asks
`NameIndex`; its mark set adds each scope's mount and every mount point beneath each scope for `FAN_OPEN_PERM`, with
`ErrMountTable` when the table cannot be read; `canRefuse` counts scopes; `settleByPath` allows on the read loop only
what neither the path nor the name refuses; supervisor R15d asks `FSIndex.NameMoveRefused` beside
`DenyReadMoveTarget`; `fallbackMutation` and `decideFS` unchanged (they already call `AdvisoryFS`). In the same commit:
`spec/record/v1` (rule forms), record-ledger §2.2 and `drift.declare` (NameDeny rule names). Tests:
*TestPlaneNameRefusalNamesTheRule* (expansion entry by path, compacted by path, declared glob, built-in label, REFER,
D5 label, unresolved sample), *TestOneLinePerNameRefusal*, *TestListenerRefusesNameMatchedOpen*,
*TestListenerAllowsNameOutsideScopeAndInDependencies*, *TestListenerMarksMountsBeneathScope*,
*TestListenerScopeRefusesOnUnreadableMountTable*, *TestNameMoveRefusedAtTier2*, *TestSupervisorRefusesNameMutationAtTier2*
(create, mknod, symlink, link onto, rename onto, unlink, truncate), `TestCrossCheckTiers` with name tables,
*TestDriftDeclaresNameEntries* (a glob that matched nothing, a built-in label); root
`fanotify_*_integration_test.go`: a `.env.local` created after Arm is refused for the run and allowed for a host
process, also on a tmpfs mounted under the scope.

**C9. Doctor, capability, compile, conformance.** `internal/doctor/planeknown.go`, `planeprobe.go` (the name map in
`MapReplacements`) gain name cells: a `.env` created after the fill refused; `.ENV` refused; `.env.example` allowed;
outside the scope allowed; beneath `node_modules` allowed; a directory moved out refused; the mode is selected only
when all pass, and doctor names a failing cell. `pkg/spec/backend` `CapReadDenyCreatedLater =
"fs.deny_read.created_later"` appended **last**, after `CapUnixDestinationKernel` (R23: no earlier row's index
moves), "twenty" becoming "twenty-one" in `capability.go` and `matrix.go`, `Valid`, `AllCapabilities`, the status and
doctor printers, with cells landlock `{false, "no: compile-time expansion only"}`, cgroup `{false, "conditional: the
plane modes, for a file created directly at a covered name; the fanotify fallback refuses opens and, best effort,
mutations"}`, bpflsm `{true, "yes: a file created directly at a covered name beneath each scope; not one reached
through a temporary name, a held descriptor or an agent-made symlink"}`, and `spec/backend/CAPABILITIES.md` in the
same commit (`TestMatrixGolden`; `internal/doctor/matrix.go`, status tests). `pkg/spec/record` `Minor` moves to the
next revision with its comment line. `internal/cli/compile.go`: the print, `PlaneColumnNote` names the name entries,
`--test` passes `dir`; goldens `TestCompileTestBPFLSMColumnGolden` and `…JSON`. Conformance (`test/conformance`, ADR
0017): a name space via `-conformance.update`: read `later/.env` (landlock allow, cgroup and bpflsm refuse), write
`later/.env.local`, create, unlink and rename onto a covered name (cgroup and bpflsm refuse), read `x/.env.example`
(allow everywhere), `node_modules/p/.env` created (allow everywhere), rename a directory out (landlock allow, cgroup
and plane refuse), D3's exempt write (allow), a checkout-created `.env.development` (refused at the plane tiers);
**The baseline stays `[]`**, and any cell that diverges is a new, documented entry with its reason. The ADR 0017
generator gains name entries: `test/conformance/invariants.go` learns them (or the generator avoids `.env*` and
declared names until it does).

**C10. Guest suites, matrix, performance.** The cells and budgets below; results in `test/vm/README.md` and
enforce-plane §10.1.

**C11. Docs reconciliation.** Listed below; ADR 0043's and ADR 0039's Status lines say built, with the acceptance
results.

### Guest (root, KVM) cells and the kernel matrix

- `internal/bpf` *TestPlaneNameEntriesDecide* (both modes, both builds, scratch slot through the test fill): after the
  fill, a `.env.local` written by a helper outside the cgroup is refused for read and write-open; `O_CREAT`, `mknod`
  fifo, `symlink`, `link` to and from, `rename` to and from, `RENAME_EXCHANGE` both ways, unlink, truncate by path and
  by a descriptor opened before the run, `O_TMPFILE` then `linkat` to `.env`, an io_uring `openat` of a covered name
  are refused; `mkdir .env`, listing and removing it are allowed; chmod of a covered file allowed; `.ENV`, `.Env.Local`
  refused; `.env.example` allowed; D3's exempt file read and written, and still after an atomic-save rename and a
  delete and re-create, and `.env.test` exempt from the prefix row; after `mv app app2` the exempt file still allowed
  (the documented drift); a nested `fs.write: [./src]` below the scope still refused; outside every scope allowed;
  beneath `node_modules` allowed; a tmpfs and a bind mounted at `node_modules` holding `pkg/.env.local` allowed (the
  mountpoint's name); a tmpfs mounted under the scope holding a new `.env.local` refused; a scope that is itself a
  mount root; a file bind-mounted over a compacted `.env` refused; a bind of a subdirectory outside the scope keeps its
  rows (D6 (f)); a declared exact and a declared prefix entry; a scope row with a corrupted identity refused and
  counted `mismatch`; **a header with the flag set and no inner name map**: a covered name refused and counted
  `norows`; **a config row deleted, and one of another gen, under a live header**: a covered name refused and
  counted; a stale-gen name row absent; two runs isolated; a forced key collision (test hook) matches nothing; **a
  helper renames a long-named file to `.env`** (stale inline bytes) and it is refused; a 255-byte name; a covered
  file 63 levels below its scope decided and 65 levels refused `bound`; two scopes with a 40-level project and a file
  30 below it decided; a directory moved out, into `node_modules`, renamed `vendor` refused; renamed within, moved
  in, the scope directory itself moved, allowed; overlay and private-clone skips unchanged; a header with the flag
  clear decides nothing by name. A tmpfs mounted with `casefold` (6.13+ rows) for the folded spelling.
- `internal/runtime/enforce/cgroup` *TestPlaneNameEntriesRunEndToEnd*: a real `tego run` at tier cgroup in each plane
  mode the guest passes and at tier bpflsm: a helper outside the run writes `.env.local` after Arm; the agent's `cat`
  fails `EACCES` with one ledger line, `mechanism: plane`, the built-in label as rule; a compacted file's refusal
  names its path; `mv sub /tmp/x` refused; `mv sub sub2` allowed; `run_start.capabilities` has
  `fs.deny_read.created_later: true` and `record_minor` the new revision. On the fallback (the test build's
  `TEGO_TEST_PLANE=fanotify`): the read refused, a create, unlink and rename onto refused by the supervisor, the
  capability false. An `fs.ask` over the scope: an approval of `.env.local` refused without a prompt; a file renamed
  to `.env.local` during the wait refused after approval (once interface 2 lands; before it, the capability false).
- Upgrade: a run on the previous build and one on the new build coexist; neither adopts the other's pins.
- *TestCompactedTableStaysAtBPFLSM*: 4,500 `.env` files under a writable worktree; compile reports compaction and the
  count dropped; an auto run gets tier bpflsm; every file refused with its expansion name; an `nlink 2` file keeps its
  row and is refused through its other name.
- Differential: the ADR 0017 generator over a name corpus (names × tree shapes × operations, mount crossings
  included) in the guest, kernel against `Evaluate` at bpflsm and at cgroup on the fallback.
- Doctor: `TestIntegrationPlaneProbeOnThisKernel` with the name cells;
  *TestIntegrationPlaneProbeRejectsAFlippedNameAnswer*.
- Rows (enforce-plane R28): RHEL 9 5.14 (lsm, rd), AL2023 6.1 (lsm, pr, no `file_truncate`), Ubuntu 24.04 6.8
  (fmod_ret), Debian 13 / RHEL 10 6.12 (lsm), Fedora 7.0 (lsm), test machine 6.17 (both boots), AL2023 with
  lockdown=confidentiality (fallback cells only), arm64 hosted runner (whatever the probe selects).

### Benchmarks and budgets

Limits fail the run (exit 1); a figure over its target and inside its limit prints `TARGET-MISS`. Figures are added
p50s per mode and per build from `openbench` (which gains `-refused` to time refused opens) in `make vm-perf`. The
`miss`, `lead` and `rename.dir` controls are the same contract with `deny_read: []` (header flag clear); the `refused`
controls are an existing covered file refused by its own row, where the walk refuses and no name check runs, so the
figure is the name check and the climb alone.

| Name | Measures | Target | Limit |
|---|---|---|---|
| `open.name.miss.<mode>.<build>_ns` | an open whose name passes no lead | 30 ns | 100 ns |
| `open.name.lead.<mode>.<build>_ns` | `.envrc`: a lead hit with no row | | 300 ns |
| `open.name.refused.<mode>_ns` | a covered `.env.local` three levels below the scope | | 1,000 ns (ADR 0039's go condition) |
| `open.name.refused.deep.<mode>_ns` | the same 32 levels below | 1,000 ns | report |
| `rename.dir.<mode>_ns` | a directory rename within the scope (two climbs) | | 2,000 ns |
| `open.excess.<mode>_ns` (kill test 4) | open+close over landlock, worst path, `summary` | | 2,000 ns, unchanged |
| `fill.name.ms` | Prepare's fill with 64 name rows and 8 scope rows, over the same table without | | 5 ms |
| `prepare.first.name.ms` | a slot's first Prepare per build, with the name map's grace period | report | 12 ms over today's |
| warm start | as enforce-plane §10.1 | 130 ms over landlock | 1,000 ms, unchanged |
| cold start | `load.plane`, `probe.programs` | report the delta | enforce-plane's cold-start limits |
| *BenchmarkListenerOpenName* | the listener's decision with names | | 200 ns, 0 allocs |
| `open.fallback.host.ms` | a host process's open on the project's own mount, marked only by the scope, at 2 and 8 runs | report | enforce-plane §10.1's listener figures |
| verifier | each plane program on each row, with its delta | | 20,000 instructions; 6 ms load (lsm, 6.17) |
| doctor | the plane probe's name cells | | +10 ms (cached per boot and build) |

The measured rows: 6.17 rd (lsm and fmod_ret), RHEL 9.8 5.14 rd (lsm), AL2023 6.1 pr (lsm), Ubuntu 24.04 6.8
(fmod_ret).

### Documentation amendments (C11, each with its dated Changes entry)

- SEMANTICS §1 (`no deny_read:` row: the `.env` part), §2 ("Globs in `deny_read`" becomes the rule: name entries,
  folding, scopes and dependency directories, mount roots, D1, D3, D5, tiers, the widening of declared globs), §2's
  walk paragraph (the climb).
- agent-contract R5 (D3's drop is the top-level file's only), R6 (the built-in entries and D3's drop), R7 (a missing
  write entry is a directory; the note), R20 (the parallel with the `deny_write` drop), the compile print and the
  `compile --test` `dir:` key.
- enforce-plane: §2.2 (the map, the header, `scope`), §2.20 built (verified instructions and deltas, timings,
  conditions), R5, R6, R7, R8, R10, R13, R21, R23, R24, R25, R28, E13 and §2.4's cap paragraph and condition 7
  (compaction, and the 1024 hard-limit hosts), §6 (casefold, dependency directories, mount roots, directory moves, a
  bind below a scope, an outside tool's symlink, the fallback), §8 invariants 4 and 10 (the name-key carve-out), §9
  (the residuals above), §10.1 (the budgets above).
- enforce-cgroup-observe (the listener's open rule, the `(deleted)` spelling, R8's marks for scopes), supervisor R15
  (the fallback's mutation refusals, F11, replacing "keeps the Landlock verdict": done 2026-10-17 by R15's
  amendment), R15d (name moves), the approval completion's name check, REASON-CHANNEL if its examples list rename
  refusals.
- limits-check-doctor-cli (doctor's name cells, the fallback's marking cost, the capability row).
- `spec/backend/CAPABILITIES.md` (C9), `spec/record/v1/README.md` (C8, C9), record-ledger §2.2 (C8).
- `docs/OPERATIONS.md` ("Row caps": 50,000 `.env` files no longer mean tier 2 where compaction applies; "Cost per
  open": the name prefilter), the examples and tests README if rename rows gain `dir`.
- `docs/FEATURES.md` E10, `docs/GAPS.md` (the residuals, the purpose's qualification), `docs/CHANGELOG.md`, ADR README
  index.

### Interfaces the supervisor must provide

Nothing here depends on how the supervisor decides its own rules. It needs three things of it:

1. **Moves.** Supervisor R15d's move refusal asks `decide.FSIndex.NameMoveRefused(src, dst string, dir bool) (rule
   string, refused bool)` beside `DenyReadMoveTarget`, in whatever race-free form R15d takes.
2. **Approval completion.** Every completion that opens or creates outside the plane (today `completeHeldAskOpen`,
   reached from `fs.ask` and from gate-held opens) asks `decide.NameRefused(h.resolved, read, modify)` (the core's
   name index, with `Evaluate` at the run's tier) about the **held object's resolved path**, `h.resolved`, and its own
   final name, beside the existing `NearestIn(...).DenyRead` check, **whatever the access mode** (D1 refuses a
   modification of a covered file, and `O_RDWR` gives a read), before the hold, so a covered path is refused
   `read-denied` without a prompt, named per D8; and **again after the approval wait**, together with
   `askScopeValid`, since an outside tool can create or rename `.env.local` during a minutes-long wait. Until this
   lands, D7 keeps `fs.deny_read.created_later` false for any run that can reach such a completion over a name scope.
3. **The fallback's mutations.** `fallbackMutation` and `decideFS` keep calling `decide.AdvisoryFS` on an
   `AdvisoryList` built by `decide` from the RuleTable (which will carry the name index); the supervisor must not fork
   that call or build its own table.

## Open questions, taken by default

1. **The built-in's scope** (default: scoped). Scoped keeps the built-in's meaning ("the project's `.env` files")
   and lets the agent create `.env` files elsewhere, such as test fixtures (`d=$(mktemp -d); echo X > $d/.env`), at the
   price of D5's refusal to move a directory out of the project in every contract. Unscoped (scope `/`) removes only
   the leave-the-project half of D5: moving a directory into a dependency directory or onto a dependency name stays
   refused unless the dependency exclusion is also dropped for the built-in, which would refuse package installs.
   Unscoped also covers other projects' `.env` files against an nx-style search and refuses creating a `.env*`
   anywhere on the host at the plane tiers, test fixtures included. Either is one compile change; scoped is
   recommended.
2. **D1's visible change** (default: accept). At the plane tiers an agent can no longer create, overwrite, delete or
   rename `.env*` files in the project outside dependency directories, unless the contract names the file. The
   breakage is listed in Users-see 3 (checkouts that add a tracked `.env.development`, `rm -rf` and `git clean` over a
   created `.env.local`, template copies, `prisma init`, `vercel env pull`, build steps). It protects an existing
   file's content and name and the agent's direct creations, not a `.env` reached by a directory move. The
   alternative, **reads and REFER only**: no creation or modification refusal from a name entry; its cost is that
   compaction is no longer verdict-neutral (a dropped row's file becomes writable), so compaction would have to keep
   every row of a file that could be written, which is nearly every compactable row; projects past the caps would
   go to tier cgroup again.
3. **D3's compile change** (default: accept). A write entry in the top-level contract naming an existing built-in
   `.env` drops it from the built-in list with a warning instead of failing compile. A veto keeps the contradiction,
   and then no per-file way out exists.
4. **D5's visible change** (default: accept). Moving a directory out of the project is refused at the plane tiers for
   every contract with the built-in list.
5. **Declared globs widen** (default: accept). An existing contract's `<dir>/<literal>` or `<dir>/<literal>*` glob
   covers that name at any depth beneath its base at tiers 2 and 3, files created later included (Users-see 7). A
   veto keeps declared globs at today's expansion and leaves name entries to the built-in.
6. **The built-in pattern** (default: no change). It misses editor backups such as `.env~` and `#.env#` (vim's
   `.env.swp` is covered by `.env.*`); extending it is a product choice about the list, not part of this ADR.

## Implementation notes

*2026-10-05 (C2: the compiler, `pkg/spec/agent`).*

- **No tier applies a name entry before one enforces it.** `agent.NameEntriesEnforced` is false until the name backend
  sets it with the plane's name rows, the backend's fill and the fallback's listener and supervisor. While it is
  false, compile still computes `RuleTable.NameDeny` and `NameExempt` (and prints them, saying no tier applies them),
  but its warnings about name entries (an entry left out over a cap, a missing write entry or an `fs.ask` entry at a
  covered name, a scope on an aliasing filesystem) are not emitted, and the glob warnings keep saying that files
  created later are not covered, which stays true until then. Why: landing the model first (as first ordered
  the name model before the name programs and the name backend) must not make `compile --test` predict refusals no run makes, nor let
  compaction drop a row the kernel still needs (C4's note).
- Name entries are compiled only where a run of the table can land at tier cgroup or bpflsm (`nameReach`), so a
  landlock-only reach compiles none, prints nothing new and makes no new syscall
  (`TestLandlockOnlyReachPrintsNothingNew`).
- The built-in entries and the scan share one predicate (`isEnvFile` is built from the entries' literals and
  exceptions) and one list of dependency directories (`EnvSkipDirs`, `IsEnvSkipDir`); `FuzzEnvNameRuleMatchesScan`
  and its 10,000-name corpus test hold D2's tie.
- D3's exemptions are compile output (`RuleTable.NameExempt`: the write entry's resolved parent, its folded final
  name, its position in `FS`), recorded only for an existing non-directory write entry of the top-level contract file
  that some entry matches; FitNameEntries allots each with the first kept entry it applies to. Such a write entry is
  a regrant, not a redundant entry (E10 does not warn it).
- D6's facts: kind, `st_nlink` and the file-mount-point flag come from the Lstat compile already makes (`meta`); the
  casefold flag is `FS_IOC_GETFLAGS` on the covered file's directory, opened `O_RDONLY|O_DIRECTORY|O_NOFOLLOW`, read
  only past `NameCompactAt` keyed paths (the table's fs rules are the count compile has), on ext4, f2fs and tmpfs, and
  inside the `.env` scan's time limit; `BindExposed` reads the mount table's device and root fields, and a mount whose
  root is the scope's own place counts as exposing it (conservative: it keeps rows).
- **D2's exceptions compare as the scan spells them.** D2 folds the whole name before the exception test, and D2 also
  requires that every name the scan matches the entries match; the two disagree on `.env.EXAMPLE`, which the
  case-exact scan denies and a folded exception would leave uncovered (`FuzzEnvNameRuleMatchesScan` found
  `.env.EXAmple`). As built, the literal part (`.env`, `.env.`) compares folded and the bytes after a prefix literal
  compare exactly with an exception's, so the entries match exactly the names whose literal part, folded, the scan
  matches with the rest as spelled: `.env.EXAMPLE` stays covered, `.ENV.example` is an exception as `.env.example`
  is, and nothing the scan denies today loses coverage. The kernel's exception arm compares the folded
  literal part and the raw tail. A D3 exemption names a folded name and cancels every spelling of it.

*2026-10-05 (C3: the decision core, `internal/policy/decide`).*

- `decide.NameIndex` (built once per table inside `FSIndex`, so the indexed `Evaluator` allocates nothing on a name
  refusal, `TestIndexedEvaluatorAllocatesNothingWithNames`) answers `Match(path, dir)` and `MoveRefused(src, dst)` by
  canonical path. `Evaluator.root`, which Evaluate's root tiers share, asks it only where the walk allowed the
  question (D1). At tier cgroup a covered write-open is the listener's `read-denied`, before the root walk. Tiers
  landlock and observe never ask it (`TestLandlockColumnIgnoresNameEntries`); no name entry turns a refusal into an
  allow on the generated tables (`TestNameEntriesMonotonic`).
- A name check whose climb cannot decide refuses `path-unresolved` named `unmatched`, as an exhausted walk is named.
- D5 in the model: at tier cgroup it is asked with R15d's `DenyReadMoveTarget`, before the ends (the supervisor's
  order); at tier bpflsm after the ends and REFER (path_rename's order). A place's coverage is the climb from the
  directory itself at level 1 (`agent.NameClimbDir`), so a directory moved to a dependency name leaves coverage; an
  entry whose scope is the moved directory itself is not asked, since the scope row moves with its inode. A climb that
  cannot decide on either side refuses `path-unresolved`. A positive destination (`RENAME_EXCHANGE`) is not modelled:
  `agent.Action` carries no exchange, as REFER's reverse arm is kernel-only today.
- Which questions ask a name entry: every fs action on a file, the exec's read of each file it opens (an exec of a
  covered file fails at its read), and a Unix bind's socket node (`path_mknod`); never a directory, and never step
  C's writability question of a mapped file (`map.go`).
- `agent.Action.Dir` and a test table row's `dir: true` carry the object's kind; `RunResolved` sets it from an
  `lstat` of an existing path.
- Deferred to the name backend, with the mechanisms that consume them: `AdvisoryFS`'s tier-cgroup branch,
  `ListenerOpen`/`ListenerOpenRefused`, `FSIndex.NameMoveRefused` and `NameRefused` (interfaces 1 and 2), and the
  recorder's `NameDecider`. They feed the supervisor's enforced refusals, the listener and the record, and a name
  answer there before the kernel enforces one would record refusals no mechanism made (ADR 0016).

*2026-10-05 (C4: the row compiler, `planerows.go`, `planenames.go`, `planeeval.go`).*

- **A scope row the walk passes** (amends D4's "a complete, verdict-neutral row"). A complete row at a scope
  directory is verdict-neutral for every question but the walk's bound: the kernel's walk stops at the first row it
  meets, so a file more than 64 steps below its nearest entry but within 64 of a scope row is answered from the row,
  where the root model refuses it `path-unresolved`; `TestNameEntriesMonotonic` caught a name dimension turning that
  refusal into an allow. A scope directory that no entry, target or exec grant keys is therefore a
  `PlaneScopeOnly` row (kind bit 6), which the walk passes as it passes `PlaneMountOnly` rows and only the climb
  reads; one that is another row's path carries its bit on that row. The name programs implements the pass in
  `tego_walk_step`.
- The plane's name check and D5 are computed from the rows alone (`DecideObject`, `ScopeMoveRefused`), as the
  kernel will, and are held to `Evaluate` by the parity tests; `RootIndex.Walk` stays the rows' walk (a table with
  name entries keeps its RootRow form, scope-only rows left out), rather than taking the name index.
- Compaction is a pure function of the table and waits on the switch, so the recorder's rows are Prepare's
  (`TestRecorderCompilesTheSameRows`) and no row is dropped while the kernel has no name rows. A directory question at
  a compacted file's path, which the kernel cannot be asked while the file is there, is answered as the dropped row
  did (refused by the file's entry), so `compile --test`'s bpflsm column stays the root model's.
- Finding (not changed): a non-entry row the plane keys (a `deny_write` chain, an `exec.allow` directory, a watch
  entry's complete row) makes the kernel's walk resolve beyond 64 steps to the deciding entry where the root model
  refuses `path-unresolved`. It predates name entries; enforce-plane §2.21 records it.

*2026-10-17 (C5 and C6: the ABI and the kernel, `bpf/include/{events,maps,plane_name}.h`,
`bpf/decide_names.h`, `bpf/decide.bpf.c`, `bpf/decide_stepb.h`, `bpf/decide_fill.bpf.c`, `internal/bpf`; the backend's
fill of the name map in `internal/runtime/enforce/cgroup` `plane.go`, `planefill.go`; begun 2026-10-16).*

- **Gated off.** `agent.NameEntriesEnforced` stays false in every product build: compile's name entries make no row,
  the slot header's `TEGO_SLOT_NAME_DECIDES` stays clear, and no hook asks a name. A binary built with
  `-tags tegotesthooks` sets the switch under `TEGO_TEST_NAME_ENTRIES=1` (`internal/cli/names_testhook.go`, ignored
  under AT_SECURE like every test variable) for the guest's governed-run cell; the name backend sets it for the build once
  the fanotify fallback's half, the recorder's naming of a compacted file, the clears and doctor's cells are built.
  Until then a run at tier cgroup on the listener would not answer names the model predicts, which is why no product
  build may set it: an `internal/cli` test held that the test hook is the module's one
  assignment and that a build without the tag runs with the switch off (switch, hook and test removed 2026-10-20, C11).
- **ABI as built** (D9, with these departures, each for the verifier of every MATRIX row). The slot header is 128
  bytes and keeps on its first cache line the four words, the lead and prefix counts, the eight lead lengths, the four
  prefix lengths, `min_len` (the shortest lead, an early out D9 put on the second line) and lead words 0 to 3. **A name
  row holds its arms summed up** rather than the arms: `deny` (the entries whose deny arm is on the row), `except` and
  `except_from` (the entries a built-in exception at the name cancels, and the literal length from which the name's
  bytes compare as spelled), `exempt` (D3's scope bits, depth 1); 288 bytes with the folded literal. Userspace sums
  them (`bpf.NewPlaneNameRow`) and refuses a row the summary cannot say (exceptions of two literal lengths on one row,
  an exemption of every entry at another depth, an entry past 63), which compile never makes; compile's cap of eight
  arms a row stands. The kernel then has no pass over arms (it cost every program that asks names about a thousand
  verified instructions). The config row, of the same size, carries `scopes` (every scope bit an entry's deny arm
  carries: D5's climbs stop once they met them all), `entries`, `bit_entries[8]`, `entry_mask[64]`, the eight
  dependency names (16 bytes each, compared byte for byte) and `dep_lens` (their lengths, so a directory whose name
  has none is not read); D9's "distinct entry masks D5 iterates" became these bit sets, so no pass loops over entries.
  `TEGO_ROW_SCOPE_ONLY` is kind bit 6 (C4's `PlaneScopeOnly`), and every walk passes it. The name map is outside the
  fill's object: userspace writes and clears it (its keys are hashes), and `tego_plane_clear` keeps to the
  inode-keyed maps. The build hash moved with the objects, and a plane is taken only with its name map: adoption
  loads every map of the specification from its pins (a pinned plane without one is not adopted), and `newBPFPlane`
  and `setInnerSpecs` refuse an object without it (`TestPlaneObjectWithoutTheNameMapIsRefused`).
- **The keys in both byte orders.** `pkg/spec/agent` `TestNameKeyVectors` pins each literal's key for a little- and
  a big-endian host (computed by a bytewise reference), and `bpf/tests` `TestNameKeysPassMatchesNameKeyInBothOrders`
  holds the kernel's key pass to `agent.NameKeyIn` in both orders through a Go transcription of its arithmetic, which
  the test pins to the C source's lines (3,000 names with capitals and stale bytes past their end); the guest runs the
  compiled little-endian pass against the same keys. No big-endian kernel was booted, so the bpfeb objects' pass is
  checked by that transcription only (the open condition below).
- **Shape of the kernel half.** A hook asks names with one global call, behind its header's flag and only where the
  walk allowed the question and the object is no directory: `tego_plane_name` reads the slot header again (gone, of
  another gen or without the flag: `path-unresolved`, counted `norows`), takes a mount root's name from its
  mountpoint (at most four stacked mounts; still a mount root after four refuses, counted), runs the prefilter, then
  calls `tego_plane_name_check` (the keys' pass, five lookups, a miss reading the config row through a lookup of its
  own, which no compare accepts, the compare pass, the rows' summaries) and `tego_plane_climb` one after the other,
  never nested.
  path_rename asks D5 through `tego_plane_move`, one direction a call. Each global function is verified once per
  program; the callbacks are straight-line arithmetic where a branch would only choose a value (`tego_nz`,
  `tego_lt`, `tego_name_mask`, the folds, the dependency compare); and every field the climb's callback changes is a
  whole word seeded with a value the verifier does not know, because the 6.8+ verifier verifies a callback again until
  the state at its call is contained, range for range and slot type for slot type, in one it verified before: a
  known 0 in one iteration and a known 1 in the next, or a byte stored as a constant beside a register's, made each
  combination a pass of its own. The hooks' decision (reason and rule) is read back through the task's scratch value
  before the record and the fallback sample (`tego_plane_settle`), so they are verified once for every path that
  decided, not once per reason a branch wrote, and path_rename's and path_link's objects' kinds (a directory or not,
  a positive destination) are read back the same way before their walks (`tego_plane_unknown`), so the verifier walks
  their chains once rather than once per combination of kinds. path_mknod's socket-bind arm moved into a subprogram
  of its own (`tego_mknod_bind`, which reads the floor from the task's record of the decision) and the record
  fallback's sample into a global function (`tego_plane_fallback_sample`, handed scalars), behaviour unchanged, so
  path_mknod's and path_rename's frames can carry the name chain; the longest chains (path_rename, `tego_plane_move`,
  the climb and its callback; a hook, `tego_plane_name`, the name check and its compare) are 480 bytes rounded as
  5.14 to 6.9 round frames. Rejected, each measured in the 6.17 guest: the first form (name check and climb as
  siblings, an arms pass, the prefilter inline in every hook, one byte a climb field: 56,000 to 89,000 verified
  instructions a program); the prefilter inline in the hooks (each of rename's two copies verified once per path into
  it: rename 22,000); the climb's fields as bytes with constants stored (6,400 for the climb alone, against 975
  seeded); the climb under the name check, and the prefilter unrolled in a frame the check stacks on (past the
  512-byte chain); a loop over the leads (its index walked back for precision at every iteration).
- **Fixes (2026-10-17, before any run used the kernel half).** (1) D5 was asked of a file: in a
  `RENAME_EXCHANGE` of a file with a directory, `tego_name_move_path` climbed from the file as if it were a moved
  directory and refused a file leaving the scope, which D5 never asks (a file is D1's, at both ends' names) and
  `decide.PlaneEvaluator.rename` allows; each direction is now asked only where it moves a directory (the guest cell
  "exchange a plain file with a directory outside", refused before the fix on 6.17 in both builds and modes, allowed
  after). (2) D2's failure paths on the probe-read build: a failed `bpf_probe_read_kernel` of a name's `hash_len`,
  its bytes' address or a word of its bytes read as 0, so the name matched nothing and the walk's allow stood, and a
  dependency directory's unread name read as none, which made D5's new place covered; every read of a name now goes
  through `TEGO_N_RDF`, which keeps the helper's error, and a fault refuses `path-unresolved`, counted, in the
  prefilter, the name check's reads and passes, and the climb (`TestNameReadsFailClosedOnTheProbeReadBuild`; the
  rdonly build's loads have no fault signal, as D2 says). The pointer reads of the climb (`d_parent`, `d_inode`, the
  mount's fields) fail as the walk's do, into an unresolved climb or a row not met.
- **Matrix fixes (2026-10-17, from the first load on every MATRIX row).** The objects above passed on 6.17 and failed
  elsewhere; each fix has a source test that failed before it, and the base objects (the tree before this change) were
  loaded on the same rows for comparison. (3) In lsm mode on RHEL 9's 5.14, Ubuntu 24.04's 6.8 and the 6.12 rows
  (Debian 13, AL2023 6.12), path_rename refused a file renamed into a stricter directory (Step A's cell "rename into a
  stricter directory", REFER's reverse arm), which the base objects allowed on the same kernels: those verifiers take
  a trusted dentry's `d_inode` for a pointer that is never NULL (`BTF_TYPE_SAFE_TRUSTED(struct dentry)`, "no negative
  dentry-s in places where bpf can see it"; later kernels make it trusted-or-NULL), so path_rename's
  `positive = new_dentry->d_inode != 0`, now materialized as 0 or 1 for the kinds' read-back, was hard-wired to 1
  (the base object's test of it after a spill and a fill kept both paths by layout alone); a negative destination read
  as positive also made a directory's rename ask the name check of the directory, which D1 never asks. The
  destination's positivity is now `tego_positive`'s test of `d_inode` read back through the task's scratch value, a
  scalar the verifier knows nothing of, and no plane code tests a `d_inode` against NULL as a value (`bpf/tests`
  `TestPlaneTestsADentrysInodeAtRunTime`; the guest cell "rename a directory named .env within the scope"). (4) On
  Fedora's 7.2 every program that asks names verified about 65,500 instructions (file_open 3,406 at base): that
  verifier keeps a map value's id past its NULL test, and the name check's five row pointers, each a lookup's value or,
  on a miss, the config row's pointer, aliased that pointer in up to 2^5 combinations, each verifying the compare pass
  anew. A miss now reads the config row through a lookup of its own, and an unused prefix length's key is 0, the
  config row's, so the five are equal up to their ids (`TestNameRowsAreEachALookupsOwn`). (5) path_mknod verified
  22,251 / 22,336 instructions (rdonly build, lsm / fmod_ret) on Fedora's 7.0 and 20,998 / 21,083 on 7.2 (18,117 and
  17,484 at base): `tego_mknod_bind` took the floor as an argument the verifier knew as 0 on one path, as a constant
  on the no-scratch path and unknown on the rest, and verified the subprogram once for each (3,300 instructions on
  7.0), and the record fallback's sample was a static subprogram verified once per call site (path_mknod has three:
  a missing header, a missing scratch value, a refusal; 1,600 instructions each). `tego_mknod_bind` now reads the
  floor from the task's record of this very decision (hook path_mknod, object dentry; without that record it refuses,
  as the floor did) and `tego_plane_fallback_sample` is a global function handed scalars (the name's address read as
  a word through the build's reader, since a load of `d_name.name` is a pointer to read-only memory on 7.0 that a
  scalar argument refuses), verified once per program (`TestPlaneFallbackOnEveryFexitHookRefusal` holds both shapes).
  Behaviour is unchanged by (4) and (5).
- **Verified instructions and verification time** (6.17 guest, 4 vCPUs, lsm; `TestPlaneLoadsAndAttaches` logs them on
  every row; the figures are the objects after the matrix fixes). Verified instructions, probe-read build / rdonly
  build, base (the tree before this change) against the name programs: file_open 3,270 / 4,997 against 8,771 / 10,435;
  path_rename 3,350 / 5,241 against 9,901 / 11,468; path_link 3,232 / 4,965 against 8,990 / 10,470; path_unlink and
  path_symlink 3,085 / 4,976 against 8,677 / 10,242; path_truncate 3,132 / 4,865 against 8,730 / 10,300;
  file_truncate 3,168 / 4,884 against 8,787 / 10,340; path_mknod 15,286 / 16,780 against 10,646 / 12,105 (its bind
  arm and the fallback's sample verified once, matrix fix (5)); every other program within 170 of its base; all
  under the plane's budget of 20,000 (the other rows are in **Verified** below). **ADR 0043's limit of 6 ms of
  verification a lsm program on 6.17 is not met, and was not before the name programs**: the base programs verify in 3 to 99
  ms (23 to 25 of either build's 28 lsm programs over 6 ms, those no name entry touches included: path_chmod 18 to
  28 ms, socket_listen 50 to 61, ptrace_traceme 9 to 11), since ADR 0024's T0 figure was the spike's small object.
  Loaded in turn with the base objects and with the name programs's objects before the matrix fixes in one guest on a busy
  host, best of seven: the name programs adds 7 to 10 ms to file_open, 9 to 14 ms to the unlink, symlink and truncate hooks, 15
  to 23 ms to path_link and 28 to 32 ms to path_rename, and takes path_mknod down 31 to 49 ms; against the objects
  before the matrix fixes, path_rename and path_link take 0 to 7 ms more (tego_positive's run-time test, the
  rows' own lookups) and path_mknod 13 to 21 ms less. path_rename first cost 98 to 133 ms more (26 ms at base to 124
  to 159): building the object without D5, without the two ends' name checks, and with the objects' kinds read
  back, showed the verifier walking rename's chain once per combination of `positive`, `files` and `dirs`, which it
  knew on each path; path_rename and path_link now read their objects' kinds back through the task's scratch value
  (`tego_plane_unknown`) before their walks (`TestNameCheckCallersAreTheListedHooks` holds the read-back). The
  load test reports every program's time and prints `BUDGET OVER` (test/perf's marker for a figure over its limit)
  for each over 6 ms on 6.17, and does not fail on it: this is an exception to "Limits fail the run" (Benchmarks and budgets, above), disclosed
  here and in the Status line, not a relaxed limit. Failing the load test would turn the matrix's main row red on a
  figure the base missed, for every package that runs it, and put a timing limit in a correctness test; the limit
  stands, and its miss is an open condition: a later cut of the verifier's work meets it, or an amendment of that table moves
  6 ms to its Target column. Cold start pays it once per mode loaded per boot and build; a pinned plane pays none. The figures
  move by several milliseconds between guests on a shared host. *Fix (2026-10-17):* the line first started
  `TARGET-MISS`, the marker the table keeps for a figure over its target and inside its limit, which read the limit as
  a target; `TestPlaneLoadLimitLineIsALimitMiss` holds the limit marker.
- **D5 in the kernel.** The new place is climbed from the new name, whose row is not looked up (the inode there after
  the move is the source's, whose bits the skip answers), where `decide.PlaneRows.ScopeMoveRefused` reads the
  compile-time row at the destination's path: for a rename over a scope directory the kernel can refuse where the
  model allows (the stricter side). A positive destination directory is asked moved the other way as well, as REFER's
  reverse arm is, since the 5.14 hook carries no flags: a directory moved over an empty directory of the project from
  outside it is refused. The deciding entry's rule names its nearest scope above the old place: the first of its scope
  bits the old place's climb met, which the climb keeps in the order it met them (`tego_climb_state.seq`).
- **Failure counts.** Every refusal for want of a name map, config row or header counts `norows`; a climb that cannot
  decide the candidate it decides counts `bound` or `unresolved` (a probe-read fault counts `unresolved`); a scope row
  whose identity is gone counts `mismatch`; each is counted once, by the global function that decides the refusal.
- **Recorder naming (minimal).** `decide.PlaneRows.RowName` and `NamedAt` resolve a tagged `rule_idx` to the name
  entry's own rule (D8's label for the built-in; `TestPlaneRowNameNamesATaggedRule`), and the bind handover's
  `RowName` with them. A file whose RuleTable entry compaction dropped is still named by the label, not by its path's
  entry, until the name backend's recorder reads the record's path (C8).
- **Verified** (2026-10-17, with the objects after the matrix fixes; in each row's `lsm=...,bpf`
  boot, both plane builds where the row offers them and both modes): `TestPlaneLoadsAndAttaches`,
  `TestPlaneStepAHooksDecide`, `TestPlaneStepBHooksDecide`, `TestPlaneStepCHooksDecide`, `TestPlaneUnixHooksDecide`
  and `TestPlaneNameEntriesDecide` pass on RHEL 9 (5.14.0-687), AL2023 6.1 (the probe-read build only: its BTF has no
  `bpf_rdonly_cast`), Ubuntu 24.04 (6.8), Debian 13 and AL2023 6.12 (6.12.107, 6.12.110), and on the test machine's 6.17
  on both boots the whole `internal/bpf` root suite (86 and 134 tests; the default boot skips the lsm mode's subtests
  only); on Fedora 7.0 and 7.2 the step C, unix and name cells pass and every program but `socket_listen` is within
  the budget, while `socket_listen` verifies 43,774 to 44,096 instructions there, at base as with the name entries,
  and fails the load test and the step A and B cells' budget check on those two rows alone (enforce-plane §2.21's
  finding). Doctor's plane probe passes both modes' known answers on every row's `lsm=...,bpf` boot (and the
  fmod_ret mode's on the 6.17 default boot). Verified instructions, lsm
  mode, probe-read / rdonly build, the largest program the name entries touch (path_rename) and path_mknod: 5.14
  10,132 / 11,489 and 10,879 / 12,127; 6.1 8,149 and 8,977 (probe-read); 6.8 9,912 / 9,845 and 11,000 / 10,780; 6.12
  10,132 / 11,489 and 10,879 / 12,127; 6.17 9,901 / 11,468 and 10,646 / 12,105; 7.0 13,047 / 16,586 and 13,732 /
  17,204; 7.2 11,478 / 15,747 and 12,163 / 16,365 (fmod_ret within about 100 of these); file_open, base against now:
  6.8 2,705 / 2,552 against 8,836 / 8,868, 7.0 3,448 / 6,971 against 11,917 / 15,553, 7.2 3,406 / 7,205 against
  10,348 / 14,714. The governed-run cell `TestPlaneNameEntriesRunEndToEnd` passed in the 6.17 guest at tier bpflsm
  and tier cgroup in lsm mode on the `lsm=...,bpf` boot and at tier cgroup in fmod_ret mode on both boots: a
  `.env.local` a process outside the run wrote after the run started is unreadable to the agent, with one plane line
  (`read-denied`, `fs.deny_read[<scope>/**/.env.*]`); creating `.env`, renaming and linking a file onto a covered
  name are refused and leave nothing; a directory moved out of the project is refused with one plane line
  (`rename-outside-contract`, `plane_reason: refer`, `fs.deny_read[<scope>/**/.env]`) and stays; a plain read and a
  move within the project go ahead. With it the plane's other governed-run cells in the cgroup package
  (`TestPlaneRunEndToEnd`, `TestPlaneRunDropsAndNamesByPath`, `TestPlaneRunNamesTrueUnderRenamesAndMountMoves`,
  `TestPlaneSecondRunAdoptsThePlane`, `TestPlaneConcurrentRunsOfOneBuildAreIsolated`,
  `TestPlaneRunUnixListenerOutcomes` and the fill's cells) passed on both boots with these objects. Kill test 4's
  open+close excess over landlock (`test/vm/perf.sh -checks open`, `record: summary`, the 6.17 guest's
  `lsm=...,bpf` boot; every product build runs with the header flag clear, so this is the flag test's cost), the
  base objects and these alternated twice: `open.excess.cgroup-lsm_ns` 1,485 and 1,297 ns at base against 1,209 and
  1,086, `cgroup-fmod_ret` 1,297 and 1,305 against 1,248 and 1,151, `bpflsm` 1,035 and 1,325 against 1,110 and
  1,156, all under the 2,000 ns limit; one earlier lone run of these objects read 2,225 ns for `cgroup-fmod_ret`
  (`BUDGET OVER`) on a busy host, which the alternated runs did not reproduce on either side. Warm start in that run:
  `start.warm.bpflsm.excess_ms` 46.6 (target 130, limit 600). The name entries' own budgets (`open.name.*`,
  `rename.dir`, `fill.name.ms`) are the name backend's, measured once a product build sets the switch (C10). The
  observe package's one-line cells with these objects passed on the 6.17 boots, AL2023 6.1 and Fedora 7.0; on RHEL 9
  they fail at their trace_proc loader's attach of `tego_exec_result` (`cannot create bpf perf link: permission
  denied`), with the base objects as with these (doctor reads those exec outcome links as optional there), so on
  5.14 those two cells, the recorder's view of the record fallback's global sample, did not run.
- **Not built here**: the name map's clears on Detach, the purge and the reaper (a cleared header makes
  the rows inert, and Prepare clears the map before it writes), the root cell for a pinned plane whose name map is
  gone (C7's *TestPlaneNameMapAdoption*), the fanotify fallback's half, doctor's name cells, the capability,
  compile's print, the conformance space, and the performance budgets (C10).
- **Fix (2026-10-25, the class of the hook's exec grant).** `bindExposed` read a mount table that
  shows no mount holding a scope as one that shows no bind exposing it: a scope's place within its filesystem is its
  holding mount's root joined with its path below the mount point, and without that mount no bind can be matched to
  it (a chroot whose root is no mount point skips the mount above it, yet lists the binds beneath). Such a scope, and
  every scope of a table that could not be read, now counts as exposed, which keeps its rows (D6 (f)'s conservative
  side); a disabled probe (`WithMountInfo("")`) still has no mount facts, and a table read in part is dropped whole
  rather than looked up unsorted (`TestBindExposedUnknownPlace`).

*2026-10-20 (C7 in part: the name map's clears, `internal/runtime/enforce/cgroup` `plane.go`).*

- **Every clear of a slot clears its name entries.** `bpfPlane.clearSlot`, which Detach, Prepare's purge of a reclaimed
  slot and the reaper all reach, zeroes the header, runs the kernel's clear of the inode-keyed rows, then deletes every
  key of the slot's inner name map from userspace (`clearNameRows`; the kernel's `tego_plane_clear` keeps to the
  inode-keyed maps, and the name map's keys are hashes userspace wrote). The inner map stays in the outer, as the fs and
  exec inner maps do: a replacement would cost a grace period on every kernel below 6.7 (`bpf.InnerIDs`). The reaper's
  `openPinnedPlanes` opens each pinned plane with its name map. Prepare still clears the map before it writes (D9).
- **Verified** in the 6.17 guest on both boots (`TestPlaneNameRowsFillAndClear`: the config row and every name row of
  the run's gen and the header's flag after Prepare, an empty map after Detach, none written by a run without name
  entries, an empty map after the reaper's clear of a live run's slot; `TestPlaneNameMapAdoption`: with the name map's
  pin removed the next run adopts no program and writes its rows into the name map its own programs read).

*2026-10-20 (C0 and the listener's half of C8: `internal/policy/decide` `cgroup.go`, `fsindex.go`;
`internal/runtime/enforce/cgroup` `policy.go`).*

- **C0.** A path the listener reads back as `<path> (deleted)` is decided under that spelling and the one without the
  suffix, refused when either refuses, by `decide.ListenerOpen` and `ListenerExec` (an exec is allowed only when both
  spellings are), and by `ListenerOpenRefused` on the table and on its index, which `Evaluate` and the supervisor's
  advisory write-open verdict ask (`TestListenerDecidesTheUnlinkedSpelling`). The root cell C0 names (a helper renames
  over `.env` while the run's open waits, by a test-hook delay) is not built: the listener has no such hook yet.
- **The listener's names.** `decide.ListenerOpenName` is the open decision's name half: `NameIndex.Match` on the
  canonical path (both spellings of an unlinked file), `read-denied` named by the entry's own rule (no `deny_read`
  entry is at a path the path half allowed, so D8's first choice never applies there), and `path-unresolved` for a
  climb the bound stops, as `Evaluator.root` at cgroup refuses it. `policy.decideOpen` asks it after the path half;
  the policy marks each scope's mount and every mount point beneath it for `FAN_OPEN_PERM`, refuses Prepare when the
  mount table cannot be read, and counts a name entry in `canRefuse`; `sortedUnder` lists every mount point beneath
  `/` for a scope `/`. With the switch off the policy held no name index (a test removed with the switch, C11).
  `TestListenerOpenNameMatchesEvaluate` holds the listener's two halves to `Evaluate`'s tier-2 write-open column on
  every generated name table. `BenchmarkListenerOpenName`: about 125 ns for a refusal, 30 ns for a miss, 0 allocs
  (limit 200 ns). The listener's existing benchmarks, base and this change alternated three rounds on four pinned
  CPUs, 0 B/op both: `BenchmarkPolicyDecideOpen` 145 and 142 ns, `…OpenRefused` 346 and 281, `BenchmarkListenerOpen`
  559 and 506 (noise), `BenchmarkPolicyDecideExec` 14.4 and 18.8 (the suffix test).
- **The fallback's governed-run cell.** `TestPlaneNameEntriesRunEndToEnd/cgroup@fanotify`: a `.env.local` a process
  outside the run wrote after the run started is unreadable to the agent (`EPERM`, the listener's `FAN_DENY`) with one
  listener line, `read-denied`, the built-in label, and readable to the host process; the cell does not judge the
  creation, the renames, the link or the directory move, which are the supervisor's half (not built).

*2026-10-20 (the supervisor's half of C8 and interface 1: `internal/policy/decide` `advisory.go`,
`fsindex.go`; `internal/runtime/supervisor` `fs.go`; supervisor R15f).*

- **The advisory verdict asks the names at tier cgroup.** `AdvisoryFS` takes the object's kind (`dir`) and, after the
  root walk allowed the question, refuses a file a name entry covers as `Evaluator.root` does: a write-open and a
  read-open `read-denied` (the listener's), any other modification with the operation's reason, named per D8 by
  `FSIndex.NameRefused` (also interface 2's question), a climb the bound stops `path-unresolved`. An end the operation
  does not follow is asked in the directory it lies in (`canonicalEnd`), an open's and a truncate's where the declared
  links lead. `fallbackMutation` enforces it unchanged (interface 3: no fork of the call). Departure: interface 1's
  `NameMoveRefused` returns the reason too, `(rule, reason, refused)`, since a climb the bound stops refuses
  `path-unresolved` under `unmatched`.
- **The object's kind** comes from the syscall where it says it (mkdir, rmdir, `unlinkat(AT_REMOVEDIR)`,
  `O_DIRECTORY`, which `O_TMPFILE` carries) and, for a rename's source and an exchange's destination, from an
  `fstatat` of where the end's walk lands (`movedKind`), made only at tier cgroup for a table with name entries. A
  stat that fails asks both D1's and D5's questions (rejected: reading it as a file, which skips D5 for a directory
  whose stat an agent made fail, or as a directory, which skips D1). Rejected: carrying the kind in the recorded flags
  (`unlinkat`'s `AT_REMOVEDIR` is recorded as no flags, record-ledger), and a separate supervisor step for the file
  question beside `denyWrite`, which would split one verdict over two places and leave `AdvisoryFS` short of
  `Evaluate`'s tier-2 column.
- **D5** is `nameMove`, after `denyWrite` and before R15d's `denyReadMove`, so the line names what `Evaluate`'s tier-2
  rename names first; each direction of an exchange that moves a directory is asked; an end whose walk failed other
  than as the task's lookup fails is refused `path-unreliable`, as R15d refuses it.
- **Residual**: a read-open of a directory named like a covered file without `O_DIRECTORY` is taken for the
  listener's refusal (`listenerRefuses`) and, under `record: full`, records no line, though the open succeeds.
- **Verified** (unit; no kernel behaviour changed): `TestAdvisoryFSNameMatchesEvaluateAtCgroup` (every generated name
  table, the spelling against both lists by index and by scan and the landing against the resolved list: a name
  never adds a refusal `Evaluate` does not make, nor misses one it makes), `TestAdvisoryFSNamesMutationsAtCgroup`,
  `TestNameMoveRefusedMatchesEvaluate`, and in the supervisor `TestSupervisorRefusesNameMutationAtTier2` (every
  notified mutation form of `fallbackMutationCases` at a covered and an uncovered name; 25 of its subtests and
  `TestNameMoveRefusedAtTier2` fail on the previous tree) and `TestNameMoveRefusedAtTier2`. Benchmarks, the previous
  tree and this one alternated three rounds on four pinned CPUs, 0 allocations and B/op unchanged on both sides:
  `BenchmarkIndexedEvaluator` cgroup 512 and 533 ns, bpflsm 399 and 382, landlock 421 and 431;
  `BenchmarkAdvisoryFS` 7,282 and 7,697 (one 9,648 outlier; medians 7,300 and 7,400); the supervisor's
  `BenchmarkNotificationRoundTrip` within its run-to-run noise (mkdir 2,754 and 3,212, write-open 2,958 and 3,052).

*2026-10-20 (interface 2: `internal/runtime/supervisor` `ask_open.go`, `ask_alternate.go`).*

- `completeHeldAskOpen`, which `fs.ask`, `fs.ask_read` and a gate-held open all reach, asks `FSIndex.NameRefused` of
  the held file's resolved path at tiers cgroup and bpflsm (`heldNameRefused`), whatever the access mode, before the
  request and again after the answer, beside `askScopeValid`, against the table then in force: a covered file is
  refused `read-denied` with no prompt, named per D8. A person's alternate is refused where a declared name entry
  covers it at those tiers (`alternateRefusal`; the built-in names were refused at every tier already). D7's
  condition on `fs.deny_read.created_later` for runs that reach such a completion therefore falls away.
  `TestHeldAskOpenRefusesNameMatchedFile` (four of its five cells fail on the previous tree),
  `TestAlternateRefusalNamesDeclaredNameEntries`.
- **The fallback's governed-run cell judges every action** (2026-10-20): `TestPlaneNameEntriesRunEndToEnd/cgroup@fanotify`
  now holds the creation of `.env`, the rename and the link onto covered names and the directory moved out of the
  project to be refused by the supervisor (R10's `EACCES`, nothing left behind, the directory stays) and the move to
  have one supervisor line, `rename-outside-contract`, named `fs.deny_read[<scope>/**/.env]`; passed in the 6.17 guest
  on both boots with the plane cells beside it (the plain suite ran no test under the
  run's filter, the tegobpf suite passed 4 and 2 cells).

*2026-10-20 (the recorder's half of C8 and drift: `internal/runtime/observe` `plane.go`, `rules.go`,
`recorder.go`, `exec_handover.go`; `internal/check/drift`; `internal/policy/decide` `fsindex.go`).*

- **A compacted file is named by its entry.** `planeFS` takes the record's path: a refusal whose `rule_idx` carries
  `PlaneRuleName` of a file with a `deny_read` entry at its canonical path (`FSIndex.DenyReadAt`) names that entry, the
  expansion row compaction dropped, as `NameIndex.Rule`'s first choice does; otherwise the name entry's own rule
  (`PlaneRows.RowName`).
- **Tier 2's recorder leaves the listener's name refusals to the listener.** `listenerOpenRefused` also asks
  `FSIndex.ListenerOpenName`, and `markedDevices` adds each name scope's mount and the mounts beneath it, as the
  listener's policy marks them, so an open the listener refused by a name is its one line.
- **Drift** declares each name entry under every name its refusals carry once the switch is on (R14).
- **Deferred to C11** (the switch): `spec/record/v1`'s rule forms, record-ledger §2.2 and the record `Minor` bump,
  since no product binary writes a name entry's rule before the switch is on.
- `TestPlaneNameRefusalNamesTheRule`, `TestRecorderLeavesListenerNameRefusalsToTheListener` (both fail on the previous
  tree), `TestDriftDeclaresNameEntries`.

*2026-10-20 (C9's capability: `pkg/spec/backend`, `spec/backend/CAPABILITIES.md`, `enforce/cgroup`
`backend.go`, `internal/runtime` `adopt_start.go`, `internal/doctor` `matrix.go`).*

- **The row** `fs.deny_read.created_later` is appended 28th, after `net.socket_families` (the first count, "twenty-one", was
  written when the list had twenty rows; no earlier row moved, R23), with the cells C9 names: landlock no, cgroup
  conditional, bpflsm yes with its residuals.
- **A run's value** is the handle's: true exactly where the plane's name check decides the run's slot, a plane mode
  with the table's name rows (Prepare writes the header's flag for them or fails). Departure from C9's text, which
  ties the value to the mode alone: a table with no name entry, or a build that compiles none, records it false, as
  `net.socket_families` is false without a `net:` section, since the row would otherwise describe a refusal no entry
  asks for. The fallback records it false (its listener and supervisor refuse best effort). A boundary adoption reads
  it from the handle as it reads the plane's other file rows. `doctor` turns tier cgroup's cell on from a selected
  plane mode in a build that enforces name entries, and both root tiers' cells off otherwise, with the reason.
- `TestNameEntryRowOfADR0043`, `TestCapabilitiesNameEntriesWhereThePlaneChecksNames`, `TestMachineMatrixNameEntries`
  (each fails on the previous tree), `TestMatrixGolden`.
- **Compile's print.** `compile --test`'s `bpflsm:` line adds `PlaneColumnNamesNote` where the plane's rows carry the
  table's name entries (`PlaneEvaluator.NameEntries`); `--test` already passed a row's `dir:`, and
  `compile`'s `names` section already prints the entries and says while no build enforces them. The
  goldens are unchanged, since a product build compiles no name rows yet
  (`TestCompileTestBPFLSMColumnNamesTheNameEntries`).
- **Doctor's name cells** (`internal/doctor` `planeknown.go`, `planeprobe.go`; `enforce/cgroup` `probefill.go`,
  `plane.go`). In a build that enforces name entries the known answers' current table also holds the built-in `.env`
  pair (`agent.BuiltInEnvEntries`, now exported) over a scope `nm/p` beneath a write row on `nm`, compiled by
  `decide.CompilePlane`; `ProbeRows` carries the name map's outer (replaced into the probe's programs) and each known
  slot's inner map, and `Fill` writes the entries through the run's own writer (`writeNameEntries`, split out of
  `putNameEntries`) and refuses a header without the flag (`nameHeaderFits`). Seven cells, every file made after the
  fill: `.env` and `.ENV` refused; `.env.example`, a `.env` outside the scope and one beneath `node_modules` passed; a
  directory renamed within the scope passed and one moved out refused; none counting. A mode is selected only when
  all pass, and doctor names the cell that failed. Departures: the cells are asked only where the build enforces name
  entries (a build that does not would deselect a mode for a check no run of it makes), and C9's list gains the
  within-scope rename, the control that keeps a kernel that refused every directory rename from passing the move-out
  cell. The compiled rows keep their positions, since the config row's entry masks are read from them by path (a
  first version that put the hand rows first wrote masks of 0 and every name cell passed; `TestPlaneKnownFixtures` now
  asserts the masks). Verified in the 6.17 guest on both boots (`TestIntegrationPlaneProbeAnswersTheNameCells`,
  `TestIntegrationPlaneProbeRejectsAFlippedNameAnswer`, with `TestIntegrationPlaneProbeOnThisKernel` and the flipped
  path-cell test, which keep their nine cells with the switch off): the seven cells took about 0.1 ms each and the
  name map's write about 80 µs, inside doctor's +10 ms budget.
- **The governed run's capability** (`TestPlaneNameEntriesRunEndToEnd`): every cell now also holds `run_start`'s
  `fs.deny_read.created_later` to the run, true in the plane modes at tiers cgroup and bpflsm and false on the
  fallback; passed in the 6.17 guest on both boots with `TestPlaneNameRowsFillAndClear` and
  `TestPlaneNameMapAdoption` (the name map's writer is now shared with the doctor's probe).

*2026-10-20 (C11's switch: `pkg/spec/agent`, `internal/policy/decide`, `internal/check/drift`,
`internal/runtime/observe`, `enforce/cgroup`, `internal/doctor`, `internal/cli`, `pkg/spec/record`).*

- **The switch is on, and gone.** `agent.NameEntriesEnforced` is deleted with every gate on it, the `tegotesthooks`
  hook `TEGO_TEST_NAME_ENTRIES` (`internal/cli/names_testhook.go`) and the tests of the off state
  (the product-build gate test's files, the decision core's and the listener's switch-off tests, the doctor's
  and drift's off cases). Rejected: keeping the variable set true, which would leave a compile-time switch no build
  flips and a test hook that changes nothing; and a runtime kill switch, which no acceptance asks for and which would
  give an operator a way to make the plane answer a different contract than the record says.
- **What every build now does.** Compile gives the name-entry warnings; the print says where the entries apply;
  `CompilePlane` emits scope and name rows and compacts (D6); Prepare fills the name map; the listener marks scopes and
  refuses by name; the supervisor's fallback refuses mutations onto covered names and D5's moves; the recorder and
  drift name the entries; doctor's known answers hold the seven name cells (16 in all) and its matrix no longer turns
  the row off for the build. A counterfactual table with no `fs`, `exec` or name entry still opens no fanotify group
  (`TestNoListenerWithoutFSRules`, `TestArmWithoutAGroupArmsNothing` clear the name entries too, since every compiled
  contract carries the built-in pair over its scan roots).
- **Record.** The name entries take no revision of their own: held reads already write these rule forms at revision
  18 (the 2026-10-27 note below); spec/record/v1 lists them, and the governed-run cell holds
  `run_start.record_minor` to `MinorHeldReads`.
- Tests that held the on state behind a helper now run as they are: the helpers (`withNames`, `withNameEntries`,
  `withNameEntriesEnforced`) are deleted. `TestRecorderLeavesListenerNameRefusalsToTheListener` keeps a discriminating
  control (a refused open of an uncovered name is the recorder's line) in place of its switch-off case; the
  supervisor's `TestNameMoveRefusedAtTier2` keeps its no-name-entries case on a table with the entries cleared;
  `TestPlaneNameRows` and `TestCompactedTableFits` keep theirs on a copy of the table without name entries.

*2026-10-20 (C10's compacted table: `internal/cli` `compile.go`; `enforce/cgroup` guest cell).*

- **Compile reports compaction.** For a table a decision plane can run, `tego compile` prints `plane     <n> per-file
  deny_read rows held by the name rows (ADR 0043 D6); <m> paths keyed` when the row compiler dropped covered rows
  (`TestCompilePrintsPlaneCompaction`, which fails on the previous tree: 1,124 `.env` files print it, 3 do not). The
  plan said "compile reports compaction" without a form; the line is printed after the table, which keeps listing
  every file, since tier landlock keeps them all.
- *TestCompactedTableStaysAtBPFLSM* (root, the lsm boot): 4,500 `.env` files beneath a write entry; compile's line
  reports at least 3,476 rows dropped; an auto run is given tier bpflsm; every file is refused with `EACCES` and has
  a plane line named by its own expansion entry; a file with a second link keeps its row and is refused through the
  other name; a plain file is read.
- **Open (first guest run, 6.17 lsm boot, 2026-10-20):** compile reported 3,488 rows dropped and 1,024 paths keyed,
  but the auto run was refused at Prepare (exit 125): composing the inherited tier-1 state, the run's Landlock plan
  needs a descriptor per `.env` file past the launcher's cap (3,830 here), which compaction does not shrink and
  compile's descriptor check (`PlaneDiagnostic`, `FitFDs` over the compacted rows) does not see. The run fails
  closed; the cell stays failing until the plan and the check agree (the name backend's next part). The default boot
  skips the cell (no lsm mode).

*2026-10-20 (`pkg/spec/agent`, `enforce/cgroup` `backend.go`).*

- **A left-out entry makes the capability false.** The first cut wrote `fs.deny_read.created_later` true
  for any plane mode with name rows, so a table whose ninth declared scope passed the 8-scope cap (compile's
  `unenforced` warning) still claimed later files of that entry refused. The table now keeps what `FitNameEntries`
  left out (`RuleTable.NameLeftOut`, compile output like `NameDeny`), and the handle's row, which a boundary adoption
  reads too, ANDs `RuleTable.NameEntriesWhole`, as D7 says (`TestNameEntriesLeftOutAreRecorded`, and two left-out
  cases in `TestCapabilitiesNameEntriesWhereThePlaneChecksNames`, each failing on the previous tree). The departure
  note under C9 above dropped D7's condition without saying so; D7 stands. `CAPABILITIES.md`, spec/record/v1 and
  record-ledger say it.
- **The compacted table's descriptors.** The open cell above traced to the inherited Landlock
  plan, not the plane: `snapshotTarget` held a descriptor for every `deny_read` target, including each one R4 leaves
  out of the ruleset because a write entry covers it, which is every file compaction can drop (D6 (g)). So a table
  of 4,500 nested `.env` files met the launcher's cap at every tier, tier cgroup at the base included. Chosen: a target
  R4 leaves out is not held; its name, which the containment plan reads, comes from a descriptor opened and closed at
  once (enforce-landlock R4, E11; `TestLeftOutDenyReadTargetsHoldNoDescriptor`, failing on the previous tree). This
  makes the plan and compile's check (`FitFDs` over the plane's keys) agree for such a table. Rejected: counting the
  whole Landlock plan in `FitFDs` (compile would only warn and fall back to tier cgroup, which composes the same plan
  and fails the same way), and releasing the descriptor after the plan (the peak would still pass the cap).
- **The recorder in a plane mode.** `listenerRefused` left an open to the fanotify listener at tier cgroup
  whatever decided the run, so in a plane mode an open the plane allowed at a name the model refuses (the plane exempts
  by the parent's inode, the model by path, D3) had no line. It now applies on the fallback only. The same assumption
  made a read under an unenforced `deny_read` entry take the path model's verdict in a plane mode (refused, or
  observed on an unmarked device) for an open the chain let through; it keeps the chain's answer there. Refuted in
  part: a 0 return on the fallback stays the listener's refusal, since from 6.13 the chain no longer carries
  `fsnotify_open_perm`'s `EPERM` (`TestOneLinePerActionWithTheSupervisor`).
- **The glob warning.** A declared glob whose name entry the caps keep had its glob warning say "files
  created later are not covered" beside the `names` section's "files created later included". Once the entries are
  settled the warning says later files are covered at tiers cgroup and bpflsm by its name entry and not at tier
  landlock; a glob with no entry, or one left out, keeps the old text (`TestNameGlobWarningSaysLaterFilesAreCovered`,
  failing on the previous tree).
- **Compile's compaction line at tier cgroup.** The line was printed only for a table that can reach tier
  bpflsm, though a tier-cgroup run in a plane mode is filled from the same compacted rows; it is printed for a table
  that can reach either plane tier (`TestCompilePrintsPlaneCompaction` gains `tier: cgroup`, which failed on the
  previous tree, and `tier: landlock`, which prints nothing). `PlaneDiagnostic` stays bpflsm's alone: at tier cgroup a
  table the plane cannot hold runs on the fanotify fallback (enforce-plane §2.4 condition 7).
- **The rename source's unknown kind.** `movedKind`'s fail-closed branch (a failed stat asks both D1's file
  question and D5's directory question) had no test, and its comment said a missing name is no directory while
  `ENOENT` is unknown too. The fake kernel takes a stat error per name, `TestNameMoveRefusedAtTier2` refuses a
  directory leaving coverage whose stat failed (it passes the mutation that reads such a source as a file only, no
  longer), and the comment says what the code does.
- **Not done in the name backend, each open:** (a) C9's conformance name space: done in
  part 4 (the note below). (b) C10's budgets: measured once (the note below); kill test 4, fill and the warm start hold with the
  flag set, and the per-open name figures (miss, lead, refused, rename) are below what the suite resolves, so they
  are neither met nor missed; open. (c) C10's matrix rows: done in part 3 (the note below): every row the ADR names but the AL2023
  lockdown and arm64 ones has run the name cells, which pass.
(d) The
  compacted table's run: done in part 3 (the note below). Until (a) to (c) hold the Status says not
  built; (b) alone is open now.
  (e) C11's remaining documentation amendments that waited on (b): done in part 3 (OPERATIONS' row caps name the
  compaction and the name caps, its cost per open the figures with the name check on; enforce-plane §10.1 condition
  7).

*2026-10-20 (the compacted table's run; `enforce/cgroup` `rules.go`,
`planerun.go`, `backend.go`; `policy/decide` `planerows.go`; `enforce/landlock`).*

- **Tier 2's unix trie in a plane run ((d) above).** `fsUnixRows` gave every `deny_read` entry beneath a write entry
  a pair of rows in the unix name trie that every run of a build shares (`UnixRowsMax` 4,096), so the 4,500-file
  table needed 9,006 and its bpflsm run was refused at Prepare. Chosen, and narrower than the design the (d) item
  above proposed (no pair for any single-link regular file): in a run a plane mode decides, Prepare chooses the plane
  before it builds the rule maps, and `fsUnixRows` leaves out the pair of a `deny_read` file the plane compacted
  (`decide.PlaneRows.CompactedAt`, D6 (g)); every kept entry, and every entry of a run on the fanotify listener, keeps
  its pair. The trie then answers that path by the write entry above it, as it answers a covered name made after
  compile; a socket node at the name is refused by the plane's D1 check, as are the file's unlink and a rename at
  either end, and the supervisor keeps every entry and decides each connect first. Rejected: a larger trie (it moves
  the cliff and changes the objects on every matrix row); counting unix rows in compile so auto falls back (tier
  cgroup on the listener cannot hold the table either). enforce-cgroup-observe §5 R7 says it
  (`TestUnixRowsLeaveOutTheFilesThePlaneCompacted`, which failed before the change with "9002 unix name rows exceed
  the trie's 4096").
- **The guest cell.** *TestCompactedTableStaysAtBPFLSM* passes on the 6.17 lsm-bpf boot (an auto run at tier bpflsm, each of the 4,500 files refused with its expansion name, the `nlink 2` file
  refused through its other name), with no skip of its own; on a boot without bpf in the LSM list its `bpflsm`
  subtest skips (root-skips) and the parent passes, so it stays in root-must-pass.
- **The descriptor ratchet.** The first cut of R4's unheld targets closed the probe descriptor at three raw sites of
  its own, which raised enforce/landlock's count past ADR 0023 A9's baseline (11 to 14) and failed `make lint`;
  `openNamed` now takes the keep decision and closes every descriptor the plan does not take at its one site.

*2026-10-20 (C10's budgets; `test/perf`, `test/vm/perf.sh`).*

- **The name check.** `perfsuite` gains a `name` check: in each plane mode, nine rounds alternate the suite's contract
  ("set": the built-in `.env` entries, the slot header's flag set) with the same contract and `deny_read: []`
  ("clear": the built-in list off, the flag clear), the order rotated as in the open check. Figures are medians of each
  run's best-of-three loop: `open.name.miss` (`out/f`), `open.name.lead` (`.envrc`) and `rename.dir` (`out/r1` renamed
  to `out/r2` and back) set over clear; `open.name.refused` and `.deep` a `.env.local` the suite makes after the agent
  is ready (compile never saw it, so only the name check refuses it) over a `.env.prod` beside it that compile keyed
  (its own row refuses it, no name check), 3 and 32 levels below the scope, in the same run (`openbench` `!PATH`: each
  open must fail `EACCES`); `start.name` the best warm start set over clear; `fill.name.ms` Prepare's fill with the
  plane's 64 name rows and 8 scope rows (58 declared globs sharing one lead over seven bases, with the built-in pair)
  over the clear contract. Limits and targets are the table's; its two "report" rows are `perf.Budget.Report` (never
  over a limit, TARGET-MISS over the target). The table's `<build>` suffix is dropped: one build remains. Departures:
  the ADR says p50s and the check reads medians of loop means, which is what `openbench` gives; `prepare.first.name.ms`,
  `BenchmarkListenerOpenName`, `open.fallback.host.ms`, the verifier and doctor rows are not part of it.
- **First figures** (6.17 bpf boot; enforce-plane §10.1 condition 7 has them all). Hold: kill test 4 with the flag
  set (`open.excess` 916 to 986 ns, limit 2000), `fill.name.ms` 0.14 ms (limit 5), the warm start set over clear
  (-9.9 to -3.1 ms, target 5). Unresolved: miss +204, +170, -376 ns; lead +516, +462, +75; rename -228, +115, -509;
  refused 456, 1028, 1058 ns at three levels and 154, 238, 4 at 32 (cgroup-lsm, fmod_ret, bpflsm). Signs that flip
  between modes and a deep refusal cheaper than a shallow one put them inside the noise between two runs of different
  contracts, so the suite's OVER lines (miss and lead in both cgroup modes, refused in fmod_ret and bpflsm) show
  neither a miss nor a pass. Chosen: the check runs only when asked (`-checks name`) with its limits unchanged, so the
  default `make vm-perf` is not failed by noise and no budget moves. Rejected: raising a limit or making a row
  report-only (a relaxed budget), and the minimum of the rounds as the figure (the open check's estimator: it gave the
  same spread, a deep refusal 415 ns cheaper than its control). Open: a design that pairs the flag within one run,
  for example two scopes in one contract, one a name entry covers and one it does not, the same file name beneath each.
- **The conformance name space ((a) above), not done here.** It needs a fixture key for a file made after compile
  (`later:`), the cells C9 lists, the generator's invariants learning name entries and the guest runs on every axis.
  The existing spaces are unchanged by enforced name entries: the ADR 0017 generator names no `.env*` file and
  declares no `deny_read` glob (its `deny_read` entries are the grid's literal depths), so no generated cell meets a
  name entry; the built-in pair is in every generated contract and covers nothing a cell touches.
- **The matrix rows ((c) above).** Run from the tip (`VM_RUN` the name cells, the
  unix cells and the plane probe): Ubuntu 24.04 6.8 on both boots, Debian 13 6.12 and Fedora 7.0 on the lsm-bpf boot.
  On each, `TestPlaneNameEntriesDecide` (rd and pr), `TestPlaneNameEntriesRunEndToEnd` (cgroup in every mode the boot
  has, bpflsm on lsm-bpf), `TestPlaneNameRowsFillAndClear`, `TestPlaneNameMapAdoption`,
  *TestCompactedTableStaysAtBPFLSM* (its bpflsm cell on lsm-bpf) and doctor's name cells pass. With the RHEL
  9 5.14 and AL2023 6.1 runs and 6.17's two boots, that is every row C10 lists but AL2023 under
  lockdown=confidentiality and the arm64 hosted runner. Found beside them, outside this package:
  `TestTier2UnixEndToEnd`'s `dgram-own` (a datagram to a socket the agent bound in its write entry) is refused with
  `EACCES` on 6.8 and 6.12 (it passes on 6.17 and 7.0); the tree without the name backend
  fails it the same way on Debian 13, so it is not caused here and
  is the unix scope's to fix.

*2026-10-20 (the name backend, part 4: C9's conformance name space ((a) above); `test/conformance`,
`spec/policy/conformance/names.yaml`).*

- **The space.** `names.yaml` is a contract whose `deny_read` is not `[]`, so it carries the built-in pair over the
  project (D10). Its new key `later` names files a process outside the run writes after the run compiled and filled
  its rules: the actor's script starts with the runner's own `await-later` action (never a cell), which prints
  `{"await":"ready"}` on stdout and waits, stat(2) only, for `await-go`; the kernel runner reads the line, writes the
  later files as the agent's, snapshots the tree the cells find and writes `await-go` (`runAwaiting`). Layout writes no
  later file, so compile, compile --test and the decide core see the tree without them. Its cells are C9's list: a
  read of a later `.env`, `.env.local`, `.ENV.Prod` (D2's folding) and a checkout-made `.env.development`; a
  write-open, an `O_CREAT` creation (exact and prefix), `mknod`, a symlink, a hard link's new name, a rename onto and
  from a covered name, unlink and truncate, each allowed at tier landlock (the expansion only) and refused at tier
  cgroup (the listener for the reads, `EPERM`; the supervisor for the rest, `EACCES`) and in the plane, named by the
  built-in labels (D8); allowed everywhere: a later `.env.example` (an exception), `.env.local` and a created `.env`
  beneath `node_modules` (D4), `mkdir .env.d` (D1 never decides a directory), a directory renamed within the scope,
  and reading and writing the files two top-level write entries name (D3); a directory renamed beneath
  `node_modules` leaves coverage and is refused where name entries are enforced (D5, named by the exact entry's
  label). The baseline stays `[]`.
- **The invariants learn name entries.** A table's model gains `names` (each exact or a prefix with its exceptions,
  with scopes), written from this ADR and the contract, never read from `NameDeny`; `invariants.go`'s name invariant
  holds D1 from them at tier cgroup and the plane (a read, and a change of a covered file's content or name, the
  dependency directories compared case-exactly from the Terms' list as written here). It does not hold D5: a cell's
  names alone do not tell a directory from a file, so the D5 cell's want holds it, and the loader keeps a table that
  declares names from declaring a directory under a covered name. `RunCapabilityCrossCheck` holds
  `fs.deny_read.created_later`: false wherever no plane mode decided the run, and true where one did for a model that
  declares its name entries. C9's other branch holds for every other table and for the generator, which name no path
  the built-in pair covers and declare no `deny_read` glob (`TestNoCellMeetsAnUnmodelledNameEntry`), so their models
  need no `names`.
- **Departure: the compile runner's build.** The unprivileged compile runner built a landlock-only tego, whose reach
  compiles no name entry (Consequence 11), so compile --test answered each name cell's root columns as if none existed
  (30 disagreements). It now builds `tegobpf` (the committed objects; no kernel call), whose reach holds tiers cgroup
  and bpflsm, so the build that runs those columns answers them; every other table's answers are unchanged.
  Rejected: compiling name entries for a landlock-only reach (it reverses Consequence 11 for a test); marking the name
  cells' root columns `no_compile` (it would leave their compile side unjudged).
- **Runs.** The handshake, the loader's checks, the invariant and the capability row have unit tests
  (`TestRunAwaitingWritesLaterFilesBetween`, `TestLaterAndNamesAreChecked`, `TestNameInvariant`,
  `TestCapabilityCrossCheck`); the decide core's `TestSharedSpecificationTables` and the compile runner pass the
  table. The kernel runner passes it on every axis of 6.17's two boots (landlock, cgroup,
  cgroup@fmod_ret, cgroup@lsm and bpflsm on lsm-bpf; landlock, cgroup and cgroup@fmod_ret on the default boot) and
  of AL2023's 6.1 (Landlock ABI 2, so its truncate cell takes tier 1's floor), with no
  fail-open, effect, problem or disagreement. The handshake costs a run nothing measurable: there `names` took 0.15 s
  on the listener axis after `fs`, which took the axis' one-time setup (14.4 s).

*2026-10-27 (the name backend on this tree).* The notes above were written on an earlier build. What the tree had
grown since meant these departures from them:

- **No record revision.** The earlier build took `record_minor` 13. The tree's revisions run to 24, and
  its held reads (ADR 0069, revision 18) already write the name entries' rule forms (`NameDenyRule.RuleName`), so the
  name backend takes none: spec/record/v1 says the forms are revision 18's, and the governed e2e cell checks `MinorHeldReads`.
- **The capability row is ADR 0069's.** The tree already had `fs.deny_read.created_later`, between
  `fs.deny_read.nested` and `fs.deny_read.moved` (31 rows), for held reads. The name backend appends no row: it gives the
  row's cgroup cell the plane's name check (conditional) and its bpflsm cell `yes` with the residuals and held reads
  beside, sets the cgroup handle's value where a plane mode's name rows decide the slot and no entry was left out, and
  leaves `runstart`'s held-reads override as it was (true wherever a run holds its reads). Tier landlock's cell stays
  held reads' `enforced (held)`.
- **Compile's prints.** The names heading (`namesWhere`) says the entries apply at tiers cgroup and bpflsm in
  every build, and names held reads at tier landlock where the table can land there and holds its reads. A kept
  glob's warning says its later files are covered at the root tiers by its entry and, where held reads hold at tier
  landlock, there too (`TestHeldReadsGlobWarningKeepsTheNameEntry`).
- **The listener and the plane.** `clearSlot` clears ADR 0048's exec pins and the name entries both; the probe's
  `ProbeRows` and `openPinnedPlanes` keep the exec pin maps beside the name map; `AdvisoryFS` checks ADR 0067's absent
  built-in rows before the tier-2 name refusal; the Landlock snapshot keeps ADR 0067's `snapshotAbsent` beside the
  R4 left-out targets' close.
- **Conformance.** The tree compiles an auto contract for a process that is not root at tier landlock alone
  (`doctor.AutoTiers`), so such a compile has no name entries (Consequence 11) and its root columns answer without
  them. The unprivileged compile runner therefore compares a cell a name entry decides only at the tiers compile's
  reach holds; the kernel runner, which compiles as root, compares the root columns. The `fs` space cell
  `read-env-created-later` now wants refused at every tier, and its model declares the built-in pair.
- **What this tree has not re-run.** Every root cell of the notes above (`test/vm/root-must-pass.txt`), the matrix
  rows, the compacted table's bpflsm run, C10's guest figures and the conformance kernel runner's name space were run
  on the earlier build only. They need the KVM run (`test/vm`) here before the status above counts them.

