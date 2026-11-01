# ADR 0124: Live controls on a running run: pause, and read and write blocks

Status: **accepted 2026-10-27**; built. Records the boundary of these controls;
who may use them is ADR 0123.

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
