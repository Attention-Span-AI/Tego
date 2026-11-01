# ADR 0077: A read the Landlock ruleset refuses is recorded when the run notifies reads for the reason channel

Status: **accepted 2026-10-25**.
Implemented 2026-10-25 at tier landlock: the contract key `reason.reads`, compile, the filter arm, the supervisor's
line, `run_start.reads_notified` and the record (minor 23). The default, `auto`, is the measured one and is **off**
(§Measurement). Amends enforce-landlock R16 and R17, supervisor R15, spec/reason/REASON-CHANNEL.md §2, agent-contract
R5's merge table (and adds its R29, the key), FEATURES S4 and E56, and the record.

## Context

Under `record: summary` or `off` tier 1's seccomp filter notifies no read open (enforce-landlock R16): notifying every
read is what makes `record: full` cost about 60 µs an open. A read the Landlock ruleset refuses under `deny_read` is
then Landlock's alone: the agent gets `EACCES`, and no line, no reason file entry and no hook payload says why. Nothing
above the engine can see such a refusal, so the reason channel's "every refusal is a `refused` event" (REASON-CHANNEL
§2) did not hold for the refusal a secret-reading agent meets first. Held reads (ADR 0069) already notify and record
every read of a run that holds them; this ADR covers runs whose reads are not held.

## Decision

1. **The key.** `reason.reads: auto | on | off` (a `reason:` section, merge class `contract-wins`). `on` has tier 1's
   filter notify every read open at tier landlock through the arm `fs.ask_read` and held reads take (`filterOpts.askRead`),
   unless something else in the table already notifies them (`record: full`, an `fs.read` gate, an `fs.ask_read` entry,
   held reads): `agent.RuleTable.ReasonReadsAt`, from `ReadsNotifiedWhy`. It never applies at a root tier, whose kernel
   record (tier 2's recorder, tier 3's plane) already carries a refused read, nor in an `--observe` run, which refuses
   nothing; and it is never part of `HoldsFSNotifications`, so a decision plane keeps deciding a root tier's opens in
   the kernel.
2. **The line.** A notified read open is answered `CONTINUE` as before: an allowed one quietly (`quietRead`), so under
   `summary` 1000 allowed reads write no line; one beneath a `deny_read` the ruleset enforces writes one `fs` line,
   `refused`, `read-denied` under that entry, from `seccomp`, with `mechanism: landlock` (`record.MechanismLandlock`),
   and Landlock's `file_open` then refuses it with `EACCES`, which the answer does not change. Every notified read open
   refused that way at tier landlock carries the mechanism, under `record: full` and `fs.ask_read` too. The line is the
   supervisor's prediction from the ruleset's own model (`decide.AdvisoryFS`), written before the kernel answers, as a
   refused write's line at tier 1 always was: a sibling that rewrites the path between the supervisor's read and the
   kernel's leaves a line naming the path the supervisor read (supervisor R15's caveat). The runtime's `refused` mirror
   now copies the action line's `mechanism` and `decision_plane`, so the reason file says which mechanism refused.
3. **One line.** Where reads are held the held floor's refusal is the one line and reason reads add no arm. At tier
   cgroup a read Landlock refuses first never reaches the fanotify listener and keeps one line; one only tier 2
   refuses is the listener's (supervisor R7a, unchanged).
4. **The record.** `run_start.reads_notified {notified, why}` on every run (record minor 23, `MinorReasonReads`): `why` is `record-full`, `gate`,
   `ask-read`, `held` or `reason` when notified; `reason-off`, `kernel`, `records-only` or `no-supervisor` when not.
   The unprivileged-tier gap (E56) no longer counts a `deny_read` entry the ruleset enforces in a run with reason
   reads; an unenforced one still counts, its allowed reads unrecorded.
5. **The default is measured** (acceptance (1)): `auto` would mean on for a run with a harness if the median per-open
   cost stayed at or under 25 µs and the offline Claude Code workload's wall time grew at most 5 %; otherwise `auto`
   means off, compile prints `reason-reads-off` with the measured cost and the opt-in `reason.reads: on`, and this ADR
   records the numbers.

## Measurement

`test/bench/read-notify/run.sh` (the opener in `test/workloads/read-opener`; tego and its supervisor confined to CPUs 0-3, the opener
pinned to CPU 1; tier landlock, `record: summary`, a `deny_read` outside the write entry; `reason.reads: on` against
`off`, alternated; medians over the repeats). Host: 16 CPUs, Linux 6.17, 2026-10-25.

| Run | Load (1 min) | Per open, on | Per open, off | Added per open | Claude Code workload, on / off | Change |
|---|---|---|---|---|---|---|
| loaded1 (20 × 20,000 opens; 5 workload runs each) | 3.3-4.2, **LOADED** | median 21.2 µs, p99 72.2 µs | median 2.0 µs, p99 4.3 µs | **19.2 µs** | 990 ms / 687 ms | **+44.1 %** |
| quiet1 (started at load 1.94 and 1.67, 30 s apart; the machine loaded during it: 20 × 20,000; 10 each) | 2.7-8.4, **LOADED** | median 28.4 µs, p99 70.7 µs | median 2.7 µs, p99 4.8 µs | **25.6 µs** | 1,573 ms / 1,231 ms (2,876 against 149 notifications) | **+27.7 %** |
| **quiet2** (started at load 1.80 and 1.58; every repeat's load 1.64-1.83: 20 × 20,000; 10 each) | 1.64-1.83, quiet | median 19.2 µs, p99 59.7 µs | median 2.0 µs, p99 3.3 µs | **17.2 µs** | 804 ms / 674 ms (2,870 against 145 notifications) | **+19.3 %** |

The workload is the interactive-claude POC's contract (`test/poc/interactive-claude`) under `record: summary`, run as
`claude -p` against the model stand-in: Claude Code's start, one Bash tool call reading 2,000 small files with the
shell's `read` builtin, and a closing turn. quiet2, the run the rule asks for (every repeat at load below 2), is the
measurement (one 4-vCPU KVM guest of this package ran in the capped slice meanwhile, and the load stayed below 2); the
two loaded runs are kept, labelled, and measured more. The per-open cost is inside the rule's 25 µs
(17.2 µs; 19.2 and 25.6 µs loaded), but the workload, whose model answers at once, grew 19.3 % (28 to 44 % loaded),
far past 5 %: Claude Code and its tool opened about 2,700 files more than the off run was told of, each now a
notification. So `auto` means **off**, and compile states quiet2's figures (`agent.ReasonReadCost`,
`agent.ReasonReadWorkload`). Only a faster notification path that kept the workload within 5 % would move the default;
the rule is not relaxed.

## Rejected

- **`record: full` by default.** It records every read, about 60 µs an open with the recorder's own work, and writes a
  line per read: the cost of this ADR's `on` and more, for every run.
- **The hook guessing from tool errors.** A Bash tool's `Permission denied` names no rule and no mechanism, and
  commands cannot be parsed into the paths they opened; a guess is not a mechanism's verdict (ADR 0016).
- **Landlock audit records.** The kernel can log a Landlock refusal (`landlock.audit`, enforce-landlock §4), but reading
  the audit stream needs `CAP_AUDIT_READ`, which tier landlock, the no-root tier, does not have.

## Consequences

- With the default, a read Landlock refuses at tier landlock under `summary` or `off` still writes no line (now said by
  `run_start.reads_notified` `reason-off` and compile's `reason-reads-off`); `reason.reads: on` buys the line at the
  measured cost. A run whose reads are held (ADR 0069) has its refusals recorded either way.
- REASON-CHANNEL §2 lists the refusals still unrecorded: the mount family's `EPERM`; a `bind(2)` with no `net.listen`
  at tier landlock (E30); reads when they are neither notified nor held; and other LSMs' refusals, recorded as
  `observed`, `by: other`, never as Tego's.
