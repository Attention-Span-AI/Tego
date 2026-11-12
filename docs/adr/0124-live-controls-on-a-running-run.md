# ADR 0124: Live controls on a running run: pause, and read and write blocks

Status: **accepted 2026-10-27**; built. Records the boundary of these controls;
who may use them is ADR 0123. Amended 2026-11-11 (below): a block "Also apply now" places for a program removed from
the contract refuses what the run's contract granted under that entry, not every name of the program's file.

## Context

Before this record a person could change a running agent in one way only: a live block (`tego block`, the run page's Block
now) of a program, a destination or a whole path. A Never allow on the event page changed the contract for the
next run and left the running one as it was, so a "never" took effect only after a restart. Two more
controls were asked for: freeze a run where it stands and let it go on, and make every narrowing edit apply to the
running run where the tier can enforce it. Both are new ways for something outside the run to change what a
governed process can do while it runs, so they need a stated boundary: who applies them, what makes them take
effect, what is recorded, and what they cannot promise.

## Decision

1. **One channel, owned by the launcher.** A pause, a resume and every live block are written to the run's
   `live-block.json` under the ledger root (the agent cannot write it) by `internal/control/runact` or the CLI,
   under one lock and one serial sequence. Only the run's own launcher reads it and applies each change, in serial
   order, one ledger line per change: `gap what=enforce`, why `live-block-added`, `live-block-removed`,
   `run-paused`, `run-resumed`, `pause-failed` or `resume-failed`, carrying `live_block` or `live_control
   {op, by, serial, at}` (record minor 24, `spec/record/v1/README.md`). Nothing writes the kernel state on the
   launcher's behalf, so the ledger line and the effect cannot disagree about which change took.
2. **Pause is the run's own cgroup freezer.** The launcher writes `cgroup.freeze` of the run's `run-<id>.scope`
   and nothing above it, and writes `run-paused` only after `cgroup.events` says `frozen 1`. A freeze it cannot
   apply writes `pause-failed` (the agent keeps running) and is retried with backoff until withdrawn. A run whose
   request waits for a person cannot be frozen (the waiting thread sits in the kernel), so the dashboard offers no
   Pause then. `tego stop` thaws first, so SIGTERM reaches a handler; a run that ends paused is thawed with no
   line.
3. **Read and write blocks narrow, never widen.** `read:<path>` refuses opens that read at or under the path, and a
   rename or link with either end there; `write:<path>` refuses changes there (open for write, create, unlink,
   rename and link at either end, mkdir, mknod, symlink, truncate, attribute changes). For every path kind a rename
   of a folder above the block is refused too. Removing a block removes only what it added. A read block is
   refused where tego does not see the run's reads (`[reads-unseen]`): it would refuse nothing. A write block is
   not offered where a kernel decision plane (`lsm`, `fmod_ret`) decides file changes without asking the
   supervisor.
4. **A capability mark, and fail closed for older launchers.** A launcher that reads a pause makes an empty
   `live-control` file in the run directory once its live-block poll runs over a cgroup of its own; `tego pause`,
   `tego resume` and the dashboard refuse a run without it (`[no-pause]`). A run whose `run_start.record_minor` is
   below 24 is refused read and write blocks (`[launcher-too-old]`), and the dashboard offers it the path block
   instead. An older launcher that meets a field it cannot read refuses the whole overlay (`live-block-unreadable`)
   and keeps the blocks it last enforced; the refusal before writing keeps a person from believing a block or a
   pause is in force when it is not.
5. **The dashboard says what is true now.** A block reads Waiting until its gap line exists, In force after; a block
   on a `tego watch` run is a mark, recorded and not enforced; a pause reads Paused only after `run-paused`.

## What this does not cover

- **A same-user process outside every run** can write `live-block.json`, the mark, or the run's `cgroup.freeze`
  directly (ADR 0123). The mark is a hint about the launcher's ability, not an authority.
- **A watched run is unconfined:** its marks refuse nothing, and its agent can leave the run's cgroup and so escape
  a pause.
- **An agent that keeps a request waiting all the time cannot be paused.** Deny it for the run or stop it.
- **A pause does not stop time-based limits:** `limits.wall` keeps counting; `tego status` may call a long pause
  `stalled` once `limits.stall_after` passes.
- **Write blocks on a tier-3 plane** refuse only the changes that still reach the supervisor; `tego block` does not
  refuse one there yet.

## Consequences

- A Never allow takes effect on the running agent at once ("Also apply now", a `read` block), with the
  same record as any other live block, and the next run gets the contract change.
- `tego` and `tego-control` must be rebuilt together, and runs started by an older `tego` restarted, before read
  and write blocks or a pause can reach them.
- Every live change is one ledger line in serial order, so `tego events --kind gap` replays exactly what was in
  force at each line.
- An Undo of a rule change that placed live blocks can lift them through the same channel
  (`runact.Block` with add false, which leaves a pause ask as it is), acknowledged like a widening and journaled on
  the undo; it never lifts a block on an ended run or one another standing change placed.

## Amendment 2026-11-11: a block from a rules change refuses what the removed entry granted

*Status: accepted 2026-11-11; built.*

**Context.** A live block on an absolute program path matches the file the path leads to by its identity (device
and inode), under every name the file has. That is right for a block a person places (`tego block <run> exec
/bin/ls`, Block now): Tego cannot know whether a multi-call program pins what it does to the name it is run by
(Ubuntu's patched uutils does, busybox and upstream uutils read `argv[0]`), so it fails closed on the file. But
"Also apply now" used the same block for an `exec.allow` entry removed from the contract. On Ubuntu 25.10 and 26.04
`/bin/ls`, `/bin/sleep` and about 113 other names are hard links of one uutils file, so removing `/bin/ls` refused
`/bin/sleep` and every other applet in the running run, while the next run's contract still allowed them. That
broke the rule this record's Consequences state for "Also apply now" (it places a block only where it refuses
nothing the new contract allows; `internal/control/rules/alsonow.go`, `blockOf`). A real run refused `/bin/sleep`
404 times under `live.block[exec:/bin/ls]`, and the agent's wait loop spun on refused sleeps.

**Decision.**

1. **A derived block refuses the removed entry's grant.** A block the rules editor places from a contract change ("Also
   apply now", Apply now; `runact.BlockFromContract`) on an absolute program path is written with `match: link`
   (`liveblock.MatchLink`). The supervisor refuses an exec under it when the running contract grants that exec under
   its `exec.allow` entry at the block's value (`entryGrants`, `liveblock.Grant`), as `execGranted` grants it: by the
   inode and the resolved path the loop fixed for the entry when the run started (the walk's image is that file and
   the walk reached it at that path, in the supervisor's own view), or by the spelling for an entry it could not
   stat then. Every other exec is left to the contract. The grant is the run's own, not what the value leads to when
   the block is placed: an agent that writes a folder the entry passes through can repoint a link there during the
   run, and the running run still grants the entry's file at its old path, so that is what the block refuses. (A first
   build matched the path the value led to when the launcher read the block; a review showed that a repointed link
   then let the old grant through, and offered no block at all when the entry was repointed at a kept name.)
2. **A person's block keeps matching the whole file.** `tego block` and Block now are unchanged and still say so ("one
   file with 115 names here"), now naming a few of the other names and the bare-name command that refuses one name.
   A person's add of a path held as a link block makes it a whole-file block (it refuses more); a derived add never
   narrows a held whole-file block.
3. **Fail closed where the grant is not known.** Where the running contract holds no file entry at the block's value
   (the run started under other rules), the link block matches as a person's does, the whole file the value leads to
   when the launcher reads it. The dashboard offers the block whenever the entries' text does not keep the program:
   it does not skip it because another kept entry leads to the same file now, since the run's own grant is fixed at
   its start and the dashboard cannot see it. Where a kept entry was fixed to the same file at the same path
   (busybox's applets, each a link to `/bin/busybox`; `/bin/ls` beside `/usr/bin/ls` on a merged `/usr`), the
   supervisor cannot tell it from an entry removed without a block, so the block refuses that file there for both,
   as the whole-file block did, though the next run would run it.
4. **An older launcher never meets it.** The overlay that holds a link block is version 5 (`VersionLink`). A launcher
   that reads it makes the run directory's `live-link` mark once its live-block poll runs (`MarkLink`), as `live-real`
   works for version 4. `BlockFromContract` writes a link block only to a run with the mark, and the whole-file block
   (version 1, as before) otherwise: never a block an older launcher would refuse to read, and never no block.
5. **No record change.** The refused line is unchanged: its rule names the blocked value, its `path` the program that
   ran. Readers say why when the two differ, through one function (`liveblock.SameFileNote`): `tego run`'s summary,
   `tego receipt` and the dashboard's refused rows read "/bin/sleep: refused, same program file as /bin/ls, which is
   blocked".

**Why this is not a loosening of what the contract says.** The block refuses less than the whole-file block did, so
this is a narrower refusal, recorded here as the quality bar asks. It loosens nothing the contract says. The removed
entry granted the running run one file at one path, fixed when the run started (`execGranted`; a hard link of a
granted file is refused by the supervisor and by the plane), and the block refuses every exec that grant admits, by
every spelling that reaches it: the name, a symbolic link to it, `/proc/self/fd/N` of a descriptor opened there,
and the old path after the agent repointed a link under the entry. Whatever the derived block leaves alone is
granted by another entry of the running contract, or refused by it under its own rule (a hard link the agent makes
in a folder it writes, the dispatcher name `/usr/bin/coreutils`), as the next run's contract refuses it. It may refuse
more than the next run (the kept entry on one path above). Two cases where the running run still runs a program the
next run would refuse are not this block's, and were there before it (read in the code, not run): an entry the rules
keep whose link the agent moved, since the next run fixes its grant afresh; and a removed entry the dashboard offers
no block for because a kept folder entry's text holds it while its link leads out of that folder
(`execStillAllowed` reads the entries' text only). `TestLiveLinkBlockRefusesWhatTheNewContractRefuses`,
`TestLiveLinkBlockKeepsToTheRunsOwnGrant` and `TestLiveLinkBlockOnARealKernel` compare the running contract plus the
block with the next run's contract case by case.

**What it does not change.** Every tier enforces live exec blocks in the same place: the supervisor's exec decision
(tier landlock; at the root tiers the fast exec handover to the plane is off while a program is blocked, so the same
code decides). It is decided on the supervisor's walk of the copied pathname, so it is best effort against an agent
that races the exec, as every live exec block was (`supervisor/liveblock.go`). Which applet a multi-call binary runs
is still its own choice from `argv[0]`, which no exec rule sees (SEMANTICS §4): on busybox or an upstream uutils build
that dispatches on `argv[0]`, a name the new contract keeps can run the removed applet, in the running run and in the
next run alike. A block on a run started by an older tego refuses the whole file, as before this amendment.
