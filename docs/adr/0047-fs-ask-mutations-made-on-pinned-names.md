# ADR 0047: a mutation in an fs.ask scope is asked and made by the supervisor on the names it pinned; one entry only; a gated mutation in a write entry is the open deputy's

Status: **accepted 2026-10-20**; (1) to (5) and (7) built 2026-10-20 for `fs.ask` scopes at every tier; (6), a gated mutation inside a write entry completed through the open deputy, decided and not built: it keeps ADR 0041 D1's (R) `completion_unsupported`. An external review of the supervisor's path reader is owed (ADR 0041's TCB, GAPS B9, E64).
Amends in part ADR 0008 (its 2026-09-21 amendment: "modifications other than open inside an `fs.ask` directory are
refused, not asked") and ADR 0041 (D1's non-open mutation rows, and rejected option 14 for `fs.ask` scopes).

## Context

- An `fs.ask` scope holds a regular-file write-open or creation for a person; every other mutation inside it was
  refused, not asked (ADR 0008, agent-contract R22, SEMANTICS §3.1). An agent that writes a file the way most editors
  and Claude Code's Write tool do (a temporary file, then `rename(2)` over the target) could not finish a write in a
  scope, and could not remove, make a directory or move a file there at all.
- The question: should an approved `fs.ask` open license the rename of that file?
- ADR 0041's principle: a supervisor decision on copied arguments is completed in the run's own kernel context,
  refused or disclosed, never continued. Its open deputy (D2) completes held opens inside the run. The first plan asked
  that mutations be completed through that deputy rather than with tego's identity, and that the choice be recorded
  here.
- The plans' concern: a mutation the supervisor makes itself bypasses the plane's REFER and ancestor
  rows, so it must stay within one entry, and a rename across entries is unsupported.

## Decision

### (1) What is asked

Inside an `fs.ask` scope that asks (not at or beneath a write entry: an ordinary grant takes precedence over an ask,
ADR 0057 D3), these are held for a person, under hold `mutation`, with the record's fs op:

| Syscall | op | target | target2 |
| --- | --- | --- | --- |
| `unlink`, `unlinkat` | unlink | the name | — |
| `rmdir`, `unlinkat(AT_REMOVEDIR)` | unlink | the directory | — |
| `mkdir`, `mkdirat` | mkdir | the new directory | — |
| `rename`, `renameat`, `renameat2` with no flag, `RENAME_NOREPLACE` or `RENAME_EXCHANGE` | rename | the old name | the new name |
| `symlink`, `symlinkat` | symlink | the link | its stored target, a string never walked |
| `link`, `linkat` (no `AT_EMPTY_PATH`; `AT_SYMLINK_FOLLOW` only onto a name that is not a symlink) | link | the existing name | the new name |

Each name is the one this process's view gives the pinned directory (its `/proc/self/fd` link, checked by inode) joined
with the final component, so the person is shown where the mutation will act, whatever spelling the agent used.

Not asked, and refused by the kernel as before (the scope grants nothing): `truncate` by path, `chmod`, `chown` and
xattr writes (tier 1 cannot refuse a chmod at all, SEMANTICS §3.1), `mknod`, `RENAME_WHITEOUT`, a trailing slash on a
name an op takes as a non-directory, a final `.` or `..`, a link from a descriptor (`AT_EMPTY_PATH`), and a
symlink whose target was too long to read whole.

A mutation the kernel fails before its permission check (a name to remove that is missing, a name to make that
exists, `unlink` of a directory, `rmdir` of a file, a rename between a directory and a non-directory) is not asked:
the syscall is continued, and the kernel's own lookup answers it, as it did before. Nobody is asked about a mutation
that cannot happen.

### (2) Who makes it: the supervisor, as the task, on the pinned names; not the deputy

The approved mutation is made by the supervisor's identity-adopting thread (ADR 0008's: the task's fsuid, fsgid,
groups and, for `mkdir`, its umask in a private `fs_struct`), with `unlinkat`, `mkdirat`, `renameat2`, `symlinkat` or
`linkat` on directories pinned `O_PATH` by a walk made as the task (`walkExec`: the task's root, its cwd or dirfd,
every symlink of the directory part followed as `filename_parentat` follows it), each with one final name that is
never followed. The syscall's result is returned to the task (`syscall_ret`); the syscall is never continued.

Not the open deputy: an `fs.ask` scope grants the run nothing in the kernel (it is compiled with no rights, SEMANTICS
§3.1), so the deputy, which is inside the run's Landlock domain and cgroup, is refused by its own domain at every tier
and by the plane at tiers 2 and 3. Completing in the run's own kernel context would need the deputy to hold a right
the run does not have: a wider Landlock domain (a second deputy restricted before the agent's domain) or a plane
exception for the deputy's thread group. Either is a new standing bypass of the run's own boundary, usable whenever
the deputy is driven, which the person's one answer never authorised.

What makes the supervisor's completion race-free instead:

- **Where it acts.** Each end is one name in a directory held by descriptor. A symlink or a directory the agent swaps
  on the path during the hold cannot move the mutation: the walk is over. This is the TOCTOU harness's assertion
  (`TestAskMutationRenameIsMadeOnThePinnedParentAfterASymlinkSwap`: the path's symlink, in a directory the agent may
  write, is repointed while the person decides; the rename is made in the directory that was shown).
- **Why the pinned directory stays where it was shown.** An end is asked only when its nearest entry is the scope
  itself (3), and then so is its directory's: every directory a scope governs is one where the run may not rename,
  create or remove a name (Landlock refuses the agent at every tier, the plane too at tiers 2 and 3). So no
  process of the run can move the pinned directory, or replace the object at its name, while the person decides.
- **Checked again before the syscall.** The completion compares each pinned directory's inode, its link count and its
  path in this process's view, and the object each name held at the pin (its `(dev, ino)`, or its absence), with what
  they are now; any difference refuses `ask-unavailable` and makes nothing. Only a process outside the run could have
  made such a change; between that check and the syscall such a process can still race, which is the host's own
  concern, not the run's.

### (3) One entry: a mutation across entries is refused as unsupported

Every end of a held mutation must lie in one `fs.ask` scope, and be governed by it (no entry nested in the scope is
nearer). A rename or link with one end elsewhere (another scope, a write entry, an entry nested in the scope, or no
entry) is refused `EXDEV`, with `completion_unsupported` and the op's `-outside-contract` reason, before anyone is
asked. `EXDEV` is the kernel's own answer to a move it cannot carry rights across (Landlock's REFER refusal), so
`mv` and most libraries copy and unlink instead, and each half is then decided, and asked, where it lands.

Why: a move across entries changes which rule governs the object. Out of a scope into a write entry, the person's
answer would hand the agent a file it may then change freely; into another scope, the second scope's question is a
different one; and the plane's REFER, ancestor and deny_read-move rows, which decide such a move in the kernel, never
see a syscall the supervisor makes from outside the run.

### (4) What no approval reaches

Before anyone is asked, each end is refused, and the person is not asked, when it is:

- a built-in `deny_write` target or the `fs.ask` scope's protected configuration (`AskDenyWrite`), or a directory
  above one (rename, rmdir and a new name alike; space 4's ancestor cells), reason the op's `-outside-contract`;
- any entry's own path, or a directory above one (the scope's own root included): no rule's subject is moved, removed
  or replaced under it;
- tego's own state (the ledger, the run's runtime directory), inside it or above it;
- under a `deny_read` entry (`read-denied`);
- in a scope whose prelaunch pin no longer names the scope (`askScopeValid`, `ask-unavailable`), checked again after
  the answer;
- one the gate refuses, scored on the held names as the agent's own mutation is scored (`gateFS`: the write
  predicates on both ends, the read predicates on a move's leaving names); an ask the gate scores carries its score
  and gate rule, and is then answered once, never remembered.

A refusal a supervisor floor made on the copied names (R15c's deny_write, R15d's deny_read move) is final: nobody is
asked to lift it (ADR 0041 D3 (1)).

### (5) An approval licenses the operation it named, on the names it showed

No: an approved `fs.ask` open does not license a later rename. The rename is its own question, naming both ends, and
only its own approval makes it. A standing answer (`--always`) for a mutation is keyed by op, rule, target and target2
exactly. In an `fs.ask` directory, Claude Code's Write tool therefore costs two questions per write: the temporary
file's creation and the rename over the file (`TestAskMutationAnApprovedOpenDoesNotLicenseTheRename`, with the rename
approved and denied). A file the agent should rewrite freely belongs in a write entry.

Rejected:
- an approved create licensing the rename of the same inode: the rename replaces the destination, a write of a file
  the person was never shown, and removes the source's name, two effects for one answer;
- a rename's standing answer keyed by its destination alone: `--always` would then let the agent move any other name
  of the scope onto the destination, removing that name and the destination's content, which nobody saw;
- asking once per directory: a scope's question is about a name, as every other ask is.

### (6) A gated mutation inside one write entry: the open deputy (decided, not built)

A mutation the gate scores into the ask range lies inside a write entry, where the run already holds the kernel
right; there the completion belongs in the run's own kernel context. Under `gate.completion: held`, the open deputy
(ADR 0041 D2) is to pin each end's directory and make the mutation itself, so Landlock and, at tiers 2 and 3, the
plane's REFER, ancestor and deny_write rows decide it in the kernel; both ends must lie in one write entry (else
`EXDEV`, unsupported, as (3)). It needs the deputy's protocol to carry the mutation ops and its allowlist filter to
admit `unlinkat`, `mkdirat`, `renameat2`, `symlinkat` and `linkat`, which widens the deputy's confinement to the run's
own rights and no further. Not built: such a mutation keeps ADR 0041 D1's (R) `completion_unsupported`
refusal. Rejected for it: the supervisor's thread, which would bypass exactly the plane rows C11 names.

### (7) Record

- The ask line carries hold `mutation`, op, target and `target2`; the answer line carries `target2` too.
- A completed mutation's fs line is the supervisor's: authority `human`, verdict `allow`, `path` and `path2` the held
  names (a symlink's `path2` its stored target), `operation_completed` (the syscall this process made returned 0),
  `syscall_ret` (its result as the task got it) and `result_unknown` when the task's syscall was gone before it was
  answered (counted `orphaned`). It is not written under `record: off` when completed; one that failed is.
- A refusal is the ordinary refused fs line: `ask-denied`, `ask-timeout`, `ask-unavailable`, `read-denied`, `fs-gate`,
  or the op's `-outside-contract` (with `completion_unsupported` for (3)).
- record_minor 28 (`MinorFSMutationAsk`).

The supervisor's syscall comes from the launcher's cgroup, not the run's, so at tiers 2 and 3 the kernel recorder and
the plane neither decide nor record it: the supervisor's line is the action's one line (ADR 0016, R7a).

## Consequences

- The same at every tier: a scope compiles with no rights at tiers 1, 2 and 3, so the run's own syscall is refused
  everywhere and the supervisor's completion is the one path; at the root tiers the supervisor adopts the task's
  credentials, so the mutation is never made with root's.
- A mutation made and then not delivered (the task's syscall withdrawn while the supervisor answered) stays made:
  there is no rollback, as for an approved create (ADR 0008). Below Linux 5.19 a non-fatal signal can restart the
  task's syscall after the supervisor made it; the restarted syscall then meets the result (`ENOENT` for an unlink,
  `EEXIST` for a mkdir), the double effect ADR 0041 D5 records for creates.
- The hot path is unchanged: a run with no `fs.ask` scope, or a mutation the kernel allows, returns before anything is
  pinned, and the held path waits for a person.
- The supervisor now makes filesystem mutations as the task. Its path reader, its walk and this completion are in the
  TCB and owe the external review and the path-reader fuzzing (E64) that GAPS B9 lists.

## Rejected options

1. **The in-run open deputy for `fs.ask` scopes** ((2)): refused by the run's own domain and plane; giving it the
   scope's rights is a standing bypass.
2. **Continuing the approved mutation** (`CONTINUE` after a person approves): the kernel re-reads the names after the
   answer, a TOCTOU ADR 0008 forbids, and the scope's no-rights domain would refuse it anyway.
3. **Re-walking the copied names at completion and refusing if they changed**: still a check-then-act on names; acting
   on the pins makes the walk's answer the one the syscall uses.
4. **Supporting cross-entry renames by checking both entries' rules in userspace**: a userspace copy of REFER and the
   plane's nearest-wins rows is the substitution ADR 0041 D2 rejects.
5. **chmod, chown, xattr and truncate asks**: tier 1 cannot refuse a chmod, so an ask there would be a question whose
   no the kernel does not keep; truncate by path is a write-open's effect without an open, left for a later decision.

## Implementation notes (2026-10-27)

- **Live blocks (record_minor 21 and 24) came after this decision.** A person's live block outranks the ask, as it
  outranks a held open: the held mutation's pinned names are matched against the run's live blocks (`liveFS`) before
  anyone is asked and again after the answer, so a block added while the person decided refuses the approved mutation,
  which is then not made (`TestAskMutationALiveBlockRefusesBeforeAndAfterTheAsk`). A user `fs.deny_write` entry (ADR
  0071) is a floor as a built-in target is: refused on the copied names (`fsDecided.floor`) and, on the pinned names,
  by the table's deny_write index before anyone is asked.
- **The ask socket's wire type** (`pkg/spec/askproto`, which moved out of the broker after this decision) carries
  `target2`, so `tego ask` and every other client see a rename's destination; the dashboard's pending ask reads it from
  the ask line and shows `old -> new`.
- **The gate's facts** for a rename or a link whose gate scores beneath a moved directory (`srcNotDir`, `dstNotDir`)
  are read from what each pinned name held, as `settleFS` reads them from its own walk.
- **record_minor 28**, not 13: revision numbers are taken in order (`TestRecordMinorsHaveNoGap`).
