# ADR 0125: Locked and Adjustable: changing a running agent's rules both ways, with time limits

Status: **accepted 2026-10-27**; built. Extends ADR 0124 (live controls) and stays inside ADR 0123's
boundary (who may change governance). This ADR builds the explicit-fence design, with the overlay's version bumps, an
acknowledgement bound to one exact change, and a golden test that proves nothing moves when the option is off.

## Context

The kernel cannot widen a run's rules while the run lives, because a Landlock domain only tightens
(landlock_restrict_self(2)). Today an operator can tighten a running run (live blocks and pause, ADR 0124) but can
loosen it only from its next run.

An agent that runs for weeks needs more:

- take a rule away for a while (minutes, a day, weeks, or until a date) or for good, and put it back, without a
  restart;
- give any live change a time limit that ends by itself and is recorded.

The kernel's allow-list cannot loosen a live process, so whatever does the loosening is weaker than the kernel. That
is a different guarantee. It is therefore a mode the operator chooses with its costs in view, not a silent extension
of today's behaviour.

The decision rests on these facts, checked in the code at the time:

- **Every tier has a supervisor and Landlock.** Every tier runs Tego's seccomp user-notify supervisor and installs
  Landlock from the contract (`supervisor/doc.go`, `enforce/cgroup/doc.go`). Every run also has a cgroup scope of its
  own (`run.go`, `createCgroup`).
- **Net is relayed.** Tego's own process makes a connect under a `net:` section, on a duplicate of the agent's socket
  (`supervisor/net.go`). The agent cannot race it.
- **Held reads can be checked on the opened file; exec cannot.** Tego's deputy completes a held read open on the
  object it pinned (`held_open.go`, ADR 0069). A refusal checked on that object cannot be raced. A refusal checked
  only on the copied name can be raced (ADR 0041, the R15c symlink race). Exec allows are decided on names and file
  identity, and nothing completes them race-free without a kernel plane.
- **The plane modes drop notifications.** At those modes Tego's filter stops notifying what the plane decides
  (`UsePlaneFilter`, enforce-plane R27). The exception is a rule table that holds fs notifications.
- **The overlay format needs version bumps.** The live overlay is written atomically under a lock
  (`liveblock/file.go`). An older decoder ignores unknown fields, so a format change must bump the version. Without a
  bump, an old writer would drop the new fields without notice. (*Amended 2026-10-27*: version 4 adds an
  entry's `real`, the path a path, read or write block's value leads to through a link. It is written only to a run
  whose launcher made the run directory's `live-real` mark, so an older launcher never meets it, and an older writer
  refuses the file rather than drop the field.)

## Decision

### 1. Two modes, chosen per contract

**Locked** is the default: a contract with no `live:` key, or with `live.mode: locked`. It is today's behaviour plus
time limits.

**Adjustable** (`live.mode: adjustable`, shown in the UI as "Adjustable (live both ways)") adds a fence:

```yaml
live:
  mode: adjustable          # locked (default) | adjustable
  fence:                    # access Tego may grant while the run runs; every entry is refused at start
    read: [~/billing-exports]
    net:  [api.stripe.com:443]
    exec: [/usr/bin/psql]
```

Every package, the CLI, the dashboard and this ADR use these two names. A contract without `live:` compiles to a rule
table that is byte-identical to today's, and a golden test proves it.

### 2. The fence

Compile adds each fence entry to the contract that the kernel layers are built from: Landlock, fanotify, the cgroup
BPF rows and the plane rows. The kernel therefore holds the run to the contract plus the fence. From the run's first
instruction, Tego's live layer refuses every fence entry until the operator lifts it.

There are only three kinds. Each is one that Tego can enforce without a race, or that the UI labels honestly as best
effort:

- **`net`**: a host or address with its port, TCP only. It is refused on the relayed connect, so it cannot be raced.
- **`read`**: a path and everything beneath it, for reads only. Read opens are held for the whole run
  (`fs.reads: held` is forced). The refusal is checked on the object the deputy opened as well as on the name, so a
  swapped symlink does not get through.
- **`exec`**: an absolute program path. It is refused on the names and the file identity the supervisor sees. This
  is **best effort**: a copy of the program under another name runs wherever the agent can write and execute.

There is no `write` kind. File changes other than opens (rename, unlink, mkdir, chmod) cannot be completed race-free
without a writer for the kernel plane.

Each entry is one of two sources:

- `new`: access the contract does not have.
- `deny`: exactly one of the contract's own refusals, which the fence takes out. It must be an `fs.deny_read` entry,
  or an `exec.deny` entry that names a whole program.

Compile refuses an entry when:

- The contract already allows it (to refuse such access for a while, use a timed block);
- it is a read entry at, beneath or above any write grant, because a file could be renamed out from under it;
- it is a read entry with a contract read grant beneath it;
- it is a read entry inside or around a `deny_read` entry other than that entry itself;
- it is a read entry at, beneath or above a program or folder `exec.allow` grants (a command pattern's program
  included), or a read entry in a contract with no `exec.allow` list (no `exec:` section, or a deny-list): running a
  program reads it, and such a grant would let the agent run, and so read, a program under the entry before it is
  lifted;
- it sits at or around Tego's own state or a built-in `deny_read` entry;
- it names any unix socket or abstract name, because the user bus and the systemd, docker and tmux sockets can start
  processes outside the run;
- it is a net entry and the contract has no `net:` section;
- it would take the fence past 64 entries;
- it comes from a `live:` key in a profile (only the top-level contract's `live:` key counts).

A loopback destination gets a warning: a local service may run commands outside the run, and Tego cannot tell.

Removing the last `deny_read` entry leaves the list nil, not empty, so the built-in credential refusals stay in force.

### 3. Lift, grant, restore

- **Lift** allows a fence entry that names a contract refusal.
- **Grant** allows a fence entry that is new access.
- Lift and grant are one operation, `lift`.
- **Restore** refuses the entry again.

Nothing outside the fence loosens while the run runs. Such a change applies from the next run: a manual restart
today. Switching mode also waits for the next run,
because the fence is built into the Landlock domain.

*Amended 2026-11-01:* as built, this covers file, program and network rules. MCP tool switches (ADR 0126 §4) and model
routes (ADR 0127) can still be loosened on a running run, Locked or Adjustable, by a person outside every run, with
confirmation: the mode check those two ADRs planned is not built (docs/GAPS.md C39). *Amended 2026-11-11:* it is
built in Tego's writers: on a Locked run `tego mcp`, `tego route` and their dashboard pages refuse a change past the
contract (`liveblock.CheckLoosening`, `[locked]`), and still take a tightening or a change back to the contract. The
MCP relay and the model forwarder do not read the mode, so a change written into the run's folder another way still
applies (ADR 0126 and ADR 0127, "Amendment 2026-11-11: Locked runs"; GAPS C39, narrowed). On an Adjustable run both
still loosen live, outside the fence.

### 4. Time limits on every live change, in both modes

A block, an unblock, a lift or a grant can last:

- **for** a duration: `45m`, `72h`, `3d`, `7w`;
- **until** a time: `2026-11-14 17:00`, `Fri 17:00`, `17:00`;
- with **no end**, meaning the rest of the run;
- **permanently** (dashboard only). The change is made live with no end, and Change rules opens for the matching edit of
  `agent.yaml` (preview, confirm, journal, undo), which the person saves; until then the next run starts without it
  (*amended 2026-11-01*: this said the edit is written with the change).

A limit can be 1 minute to 400 days.

Each limit is judged on two clocks: the wall clock, and CLOCK_BOOTTIME as the launcher pinned it the first time it saw
the instant. A limit always ends on the tighter side:

- a block's limit ends only when both clocks have passed it;
- a lift's or an unblock's limit ends as soon as either clock has passed it.

So a clock step never lengthens a loosening or shortens a narrowing.

Every match checks the limit, so the change takes effect at the exact instant. The launcher writes its ledger line on
its next poll, within 500 ms.

A limit stops new access only. Data already read or copied, files still open and connections already made all stay,
because Linux cannot revoke a descriptor.

### 5. The launcher is the authority

- **Fence state lives in the launcher's memory.** The launcher seeds the fence refusals from the compiled table into
  the first live set, before the supervisor lets the agent run. The overlay (`live-block.json`) carries requests
  only.
- **A lift must carry a MAC under a per-run key.**
  - The key is `live-key`: 32 random bytes, mode 0600, made by the launcher in the run directory. The run directory
    is under the ledger root, which the agent cannot read.
  - The MAC is an HMAC over the run, the change's serial, op, kind, value, author, time and limit.
- **The launcher refuses some lifts.** It writes a `live-lift-refused` line, and loosens nothing, for a lift:
  - whose MAC does not check;
  - outside the fence;
  - on a Locked run;
  - whose limit has already passed.
- **A restore needs no MAC**, because it narrows.
- **Ledger lines come from what took effect.** They are written from the launcher's own state transitions, never
  from the writer's change list. A lift's line is queued before the loosened set is stored.
- **A broken overlay fails closed in both directions.** An unreadable or removed overlay drops every lift, so the
  fence refusals are back in force. An unreadable overlay keeps the blocks last read, as ADR 0124 does; a removed
  one asks for no blocks, as it always did under ADR 0124 (see Notes from building the launcher's fence). An overlay
  that is unreadable at the run's start still gives the first set every fence refusal, and the launcher refuses to
  start a run whose first set lacks one.
- **Crashes end the run.** A launcher crash ends the run, and a new run starts with every fence entry refused. If the
  supervisor loop of an Adjustable run stops after start, the run is ended.

### 6. Every enforcement path forced, or no start

At the plane modes, Adjustable keeps every fs notification. Nothing a fence entry covers is then decided where Tego
cannot see it. When the fence has read entries, Adjustable also holds read opens.

The launcher refuses to start an Adjustable run when any of these holds:

- it has no run directory;
- it has no supervisor;
- it is an observe run or an adopted run;
- a notification was dropped;
- its reads are not held;
- The contract sets `io_uring: true`, whose ring connects and opens never reach the supervisor (compile refuses the
  pair too);
- its run directory lies under no enforced built-in `deny_read` entry, so the agent could read `live-key` (a ledger
  root that holds the project, HOME or a write entry).

### 7. Tiers: cgroup and bpflsm only

Compile refuses Adjustable when `tier: landlock` is pinned. The launcher refuses it when `auto` resolves to landlock.

This is a policy choice, not a kernel limit: held reads and the net relay work at landlock too. Adjustable is kept to
the tiers where its live refusals can move into kernel checks Tego already runs there: fanotify's exec-image check,
the cgroup BPF rows and the plane maps. That way one mode keeps one promise.

### 8. Who may loosen

ADR 0123's boundary applies, plus the following:

- **Dashboard.** Lift and Grant need the preview-bound acknowledgement and an explicit checkbox. The acknowledgement
  binds the run, the kind, the value, the absolute limit, the permanent flag and the overlay's serial at preview
  time. A stale or replayed preview writes nothing.
- **CLI.** `tego lift` and `tego grant` need the word typed at a terminal, or `--yes`.
- **Never from inside a run.** Both are refused from inside any run: by `SelfGoverned`, which decides by cgroup and
  fails closed, and by the dashboard's governed-peer refusal.
- **Narrowing, as built.** `runact`'s block and restore have no check of a caller inside a run, because they narrow.
  They are still not open to one through the dashboard, which refuses every POST whose connection was made inside a
  run, narrowing ones included. And an Adjustable run starts only with its run directory under an enforced built-in
  `deny_read` entry (decision 6), so that run cannot reach the overlay at all (*amended 2026-11-01*: this said block
  and restore stay allowed from inside a run).

### 9. Records (minor 26, `MinorLiveModes`)

`run_start` carries two fields on Adjustable runs only: `live_mode: adjustable`, and
`live_fence {sha256, entries[{kind, value, source, rule}]}`.

`live_block` gains `until` and `refused`. The new ops are `expire`, `lift` and `restore`. The new whys are
`live-block-expired`, `live-unblock-expired`, `live-rule-lifted`, `live-rule-restored`, `live-lift-expired` and
`live-lift-refused`.

Two kinds of event carry the rule `live.fence[<kind>:<value>]`, never a contract rule:

- a refusal by a fence entry;
- an action allowed only because a fence entry is lifted.

So the ledger never says the contract allowed what the live layer allowed. A refused lift that names no fence entry
(refused `outside-fence` or `locked`, or `mac` for a path outside the fence) carries the request's rule
`live.lift[<kind>:<value>]`, so no line names a `live.fence[...]` rule that `run_start.live_fence` does not list.
A reader at record minor 26 takes either rule on a `live-lift-refused` line, whatever the refusal: a launcher built
before the launcher's fence (at the same revision) wrote every refused lift under `live.fence[...]` (*amended 2026-10-27*, so the builds agree on a valid line).

In an Adjustable run, an exec of a program under a read fence entry that is not lifted is refused under that
entry's rule (read-denied), and every exec is decided by the supervisor while the fence has a read or exec entry.
The supervisor decides it by name, so it is defence in depth. The kernel holds it as it does in a Locked run: no
`exec.allow` grant lies at, beneath or above a read entry, so Landlock grants no execute there. At cgroup, the
entry's mount and every mount point beneath it stay marked for fanotify's exec check, which refuses every exec there,
whether the entry is lifted or not. At bpflsm the plane decides every exec in the kernel, on any mount.

## The two modes compared

This table is shown wherever the mode is chosen: Set up a new agent, `tego init`, the Rules page and
docs/user/live-modes.md.

| | Locked (default) | Adjustable (live both ways) |
|---|---|---|
| What holds the fixed rules | The whole contract: Landlock and Tego's supervisor at every tier, plus fanotify and BPF at cgroup and bpflsm. At landlock the supervisor, not the kernel, decides hosts, and command rules and `deny_write` targets are best effort (`spec/backend/CAPABILITIES.md`; *amended 2026-11-01*: this row said only what the kernel holds) | The fence: the contract plus every fence entry. Inside the fence, Tego's live layer refuses each entry until you lift or grant it |
| Loosen while it runs | No: from the next run. MCP tool switches and model routes are the exception (decision 3) | Yes, fence entries only, each one previewed, confirmed and recorded, optionally for a time. MCP tool switches and model routes are the same exception |
| Tighten while it runs | Yes: live blocks and pause | Yes: the same, plus Restore |
| Time limits | Blocks and unblocks | Blocks, unblocks, lifts and grants |
| What a compromised agent can do | What the contract allows. A live block on a file or a program can be raced with a symlink; reads that Tego holds cannot be. A `net` block on a TCP destination cannot be raced on an IP socket, and a datagram can (*amended 2026-11-01*, GAPS C47) | The same, plus: it can dodge an exec fence entry not yet granted by copying the program to a place where it can write and run. Net fence entries are TCP only; they and read entries cannot be raced. It can never lift its own rules |
| If Tego's supervisor stops | Notified calls fail and the run ends; the kernel still holds the contract | Notified calls fail and the run ends. Every open, connect and exec is notified, so none reaches a fence entry in between. Descriptors already open work until the run is killed |
| Tiers | All | cgroup and bpflsm; refused at landlock (a policy choice) |
| Performance | Baseline | With read entries, each read open costs about 0.1 ms more (ADR 0069). The plane modes run the full seccomp filter |
| What the ledger proves | Every refusal, under contract rules or `live.block[...]`, and every block change | The mode and the fence's digest in run_start; every lift, restore, expiry and refused lift as the launcher applied it; every action under `live.fence[...]`. It does not prove that the kernel enforced the live policy: the live layer did |
| Who can loosen it while it runs | Nobody for file, program and network rules. MCP tool switches and model routes: the operator, from outside every run, with confirmation | The operator, from outside every run, with confirmation; never the agent. A same-user process outside every run that reads the run's key can too (see What is left over) |

## Security argument

- **No kernel access is added beyond the fence.** The kernel never holds the run to less than the fence, and no
  overlay content can add kernel access. A lift can only remove a refusal the launcher seeded from the compiled
  table. A grant outside the fence is refused.
- **The agent cannot loosen its own rules.**
  - The overlay, the run key, `agent.yaml`, the journal and the ack key are all Tego's own state. agent-contract R6a
    and R10 keep the agent from writing it. A ledger root that also holds what the run needs stays readable, with a
    `ledger-readable` warning, and a contract file may be read. Compile keeps that state out of every fence.
  - `runact.Lift` refuses a caller in any run's cgroup.
  - The dashboard refuses a socket made inside a run.
- **Races inside the fence.**
  - Net is decided on the relayed connect, and read on the pinned object.
  - Exec is decided on names, which is best effort, and the UI says so.
  - A decision that read the old set stands for that one syscall.
- **If the supervisor stops,** notified calls fail with ENOSYS and the run is ended. Every path is forced to notify,
  so no open, connect or exec reaches a fence entry in between. Descriptors already open keep working until the
  reaper's `cgroup.kill`.
- **Replays and forgeries fail.** A replayed or forged loosening fails one of two checks:
  - the MAC, which uses a per-run key and binds the change's serial;
  - The dashboard acknowledgement, which binds the serial, the limit and the permanent flag.
- **What is left over.**
  - A same-user process outside every run that reads `live-key` can lift fence entries with no acknowledgement and
    with a `by` of its choosing. Under Locked, such a process could only remove blocks.
  - Such a process already holds all of the user's authority: it can read what the fence guards for itself. The fence
    bounds what it can hand to the agent, and every lift gets a ledger line the operator sees.
  - An agent can plant such processes (git hooks, shell rc files, autostart entries) wherever its write grants reach.
    That risk exists under Locked too.

## What stays the same in Locked

- **With no `live:` key, everything is the same:**
  - The compiled table (golden test);
  - The overlay bytes when no time limit is used (golden test);
  - The ledger lines;
  - The run, log and approval pages.

  The run page shows no mode chip.
- **What changes for every run:**
  - `run_start.record_minor` becomes 26 ;
  - the Block now form and the CLI offer time limits;
  - the Rules page names the mode ("Mode: Locked");
  - a live read or path block also refuses on the object a held read pinned, which only tightens.

## A run that did not opt in

The table shows what a Locked run's rule mechanisms could loosen while the run runs:

| Rule mechanism | landlock | cgroup | bpflsm |
|---|---|---|---|
| fs read and write grants (Landlock) | tighten only | tighten only | tighten only |
| Destinations under `net:` (relayed connect) | could loosen | could loosen (BPF rows too) | could loosen |
| `deny_read` inside a grant (held reads, fanotify marks, plane rows) | could loosen when reads are held | could loosen | could loosen |
| `exec.deny` inside a granted folder | could loosen | could loosen | could loosen |
| Live blocks | unblock: yes | yes | yes |

"Could loosen" means the mechanism allows it. Tego does not loosen any of these, by design. Locked's promise is
"never looser than its contract while it runs", and making that promise depend on which mechanism a rule uses would
make it impossible to explain.

A Locked run loosens from its next run. To loosen live,
choose Adjustable for the next run.

## What this does not cover

- **Not fence entries yet:** write access, built-in credential refusals and unix sockets.
- **Access already used cannot be taken back:** data read or copied, open files and live connections.
- **Exec fence entries are not race-free** at any tier yet.
- **A lift does not outlive its run.** A new run starts with every fence entry refused.
- **Adjustable at tier landlock** is refused.

## Consequences

- An operator can take a rule away from a long-running agent, and put it back, for any duration or for good, without
  a restart. Each change is previewed, confirmed, recorded and, when permanent, journaled and undoable.
- Time limits work for every run, Locked included.
- Adjustable costs held reads and the full filter, and it is weaker than Locked by exactly the fence. The comparison
  table says so wherever the mode is chosen.
- `tego` and `tego-control` must be rebuilt together. A run started by an older `tego` gets no time limits
  (`[launcher-too-old]`) and no lifts (`[locked]`).
- The dashboard binds a lift's confirm to its preview with the rule service's acknowledgement
  (`rules.Service.LiveAck`: the run, the entry, the absolute limit, the permanent choice and the overlay's serial)
  and checks it against the overlay as it is when the confirm arrives. The check and runact's write run under one
  dashboard lock that restores take too, so a second confirm of the same preview is refused; a change another writer
  (the CLI) makes between them is not caught by the acknowledgement, while the launcher's MAC check and its ledger
  line still hold, and the fence panel shows only what the launcher applied. A "permanent" lift or block is
  the live change with no end plus a separate Change rules edit the person makes (its own preview and confirm); the
  dashboard does not write `agent.yaml` by itself.

## Notes from building the launcher's fence

- **Where the fence lives.** `internal/runtime/livefence.go` holds it. `startLiveBlocks` seeds it, and writes the run's
  key, before the overlay's first poll, so the first Set the supervisor loads refuses every entry. An exec entry is
  refused by its path, by each of its helper images and by its `exec.deny` name, all under the entry's own rule.
- **A removed overlay.** It drops every lift. Its blocks go too, as they always did under ADR 0124: a file that is not
  there asks for no blocks. Only an unreadable overlay keeps the blocks last read.
- **If the supervisor stops.** A loop that returns an error after it started already ended every run, Locked included:
  the run's worker group fails, its context ends, and the launcher kills the cgroup. A loop that returns nil after it
  started is a listener hangup, which the kernel gives when the last task under the filter exits. A Locked run is
  left alone then, and its kernel layers still hold the whole contract. An Adjustable run waits up to 2 s for its
  cgroup to hold nothing but the open deputy. If anything else is still there, the run is ended.
- **Naming a lifted read.** A held read is named by the supervisor's floor, not by `decide.Evaluate`. Once a read
  fence entry is lifted, the floor names the read after the entry too.
- **A lift's shortest limit.** `runact.Lift` holds every limit to 1 minute or more, as it does a block's.
