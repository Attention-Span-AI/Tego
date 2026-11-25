# ADR 0165: tokens and cost_usd budgets that count across restarts

Status: **accepted 2026-11-24**; built. The number is the next free
one under `docs/adr` for this line. Record revision stays 41, which no release carries yet: one optional field,
`run_start.limits.window`, is added to it (decision 8).

## Context

Every budget is per run (R1, R2). A run that ends and starts again, which is what `tego-agent@.service` does after a limit
(124) or a crash and what `tego-agent-restart@.timer` does every night, begins its `tokens` and `cost_usd` at zero. An
agent deployed to run all the time therefore has no daily cap: a cap of $5 is $5 for each of the twelve restarts the unit
allows in half an hour. The ledger already holds what each run spent, in the `usage` of every `ssl_response`, so the
question is how a later run may count it without trusting anything the agent could reach.

## Decision

1. **A contract opts in with `limits.window`.** `limits: {tokens: 1000000, window: 24h}` makes `tokens` and `cost_usd` a
   total over the last 24 hours across every run of this agent, this run included. A contract without `window` counts per
   run, as before. The span is from 1 minute to 30 days (30 days is the default retention); `wall`, `stall_after` and
   `repeats` stay per run, since a day's wall time or streak is not a budget anyone asked for. A `window` with neither
   `tokens` nor `cost_usd` bounded is a compile warning (`redundant-rule`): it limits nothing.
2. **The ledgers are the only source.** Before a run starts, `internal/runtime/budgetwindow` lists the ledger root, takes
   the runs of this agent that were not proved to have ended before the window began, and reads every `ssl_response` in them
   (`ledger.Usage`, the one decode the watcher and `tego measure` share). No counter file, no database and no state
   directory exists; there is nothing for an agent to reach, and nothing to lose or to rebuild. The number can be
   recomputed by anyone from the ledgers and the price table.
3. **A run of this agent counts only what verifies, and only a run of this agent can refuse a start.** Whose a run is
   comes from its first line alone, read before anything else of the run (`peekOwner`): a run whose first line is another
   agent's is left there, whatever its state, its chain or its tail look like, so another agent's cut, edited or garbled
   record never blocks this one. A run that is this agent's is verified in the same pass that counts it
   (`Reader.VerifyAlong`): its hash chain, and for a run that ended, its head against the account's `chain.log`. One that
   fails, or cannot be read, is `budgetwindow.ErrUnprovable` and the start is refused, exit 125 `[budget-window]`, with the
   run's id marked "(this agent's)", the cause, and the fix: restore the ledger or its `chain.log` line from a copy, or
   move the run's directory out of the ledger root, which keeps the record and stops counting its spend (waiting does not
   help: a run that does not verify never will). The alternative, to count what is readable and go on, lets whoever can
   shorten a ledger lower the count; the window exists to be a cap, so refusal is the way to fail for a run that says it is
   this agent's. A run whose first line cannot say whose it is (it does not decode, is not a `run_start`, the events file
   is a link or a directory, or a directory of another account that this launcher cannot open) is left out and reported:
   `gap what=limits why=window-unattributed count=N` and a log line. The one such run that is not left out is a record this
   launcher's own account owns and cannot open: a mode taken off it (chmod is the one thing a held agent can still do to
   its records, and `tego run` restores those modes at its start), which is refused with the chmod that fixes it. Leaving
   out a record that names no one is the same loss as a deleted one (stated below), made by someone who can write the
   ledger root, and is said in the run's own record instead of being silent.
   A run directory whose name is another host's run id (a ledger root shared between machines) is not opened and not said:
   its chain belongs to that host's `chain.log`, and only someone who can write the ledger root makes one, as for the
   losses above.
   **An ended run with no `chain.log` line** is what an honest failure to write the anchor leaves (`tego run` says "anchor
   not written"). It was refused until `tego gc` deleted it, which for a window of days is days of no start and a fix that
   destroys evidence. It is now counted as the record holds it, after its chain verifies on its own, which is the same
   check a run that never ended gets (decision 6), and the run says it: `gap what=limits why=window-unanchored count=N`
   and a log line. Nothing is lost against the old rule: the line in `chain.log` is the proof that nothing was cut after
   the run closed, and its absence proves nothing either way; the agent cannot remove a line from `chain.log` (the
   account's `~/.tego` is outside what a held run may write), so an anchored run still has to match its line.
4. **Who is "this agent" (permanent).** The identity is what the run's own `run_start.contract_source` says, so a
   ledger written by one build is read the same by every later one, and it can only be extended, never changed:
   - a contract named in the **user** registry (`tego run --agent NAME`, registry `user`): `name:user:NAME`. The user
     registry is one folder per account, where a name is one agent;
   - a contract named in the **project** registry (the working directory's `agent.yaml` or `.tego/agents/NAME.yaml`):
     `project:NAME@<absolute path of the contract file>`. The project registry is not machine-wide, so `bot` in `/a` and
     `bot` in `/b` are two agents with two budgets and two locks, and neither is refused for the other being live (the
     first build keyed it by the name alone, which made them one, and the second, started under a restart policy that
     never retries 125, stayed down). An agent whose folder is moved starts a new count, since a folder is what the
     project registry names; the path is the one the registry resolved, as recorded;
   - a contract given by **path**: `path:<absolute path>`, so `--agent NAME` and the same file by path are two agents with
     two budgets: the operator picks the form and keeps it (a unit file names one).
   A run with none of these (a generated contract) cannot have a window and is refused with that reason. The contract's
   contents are not part of it: editing a contract does not forgive what it spent. The identity is operator-chosen:
   renaming the agent, moving its folder or switching the form starts a new count, and nothing the agent can do changes it.
5. **One run of an agent at a time.** A run takes a lock in the ledger root, `.window-<hash of identity>.lock`, an
   `flock` held until the run's ledger is closed and anchored. A second run of the same agent finds it held and is
   refused (`ErrLive`). Two runs of one agent would each count the other's spend as it was when they started and spend
   up to twice the cap. The reader also refuses a run of this agent that still holds its own ledger lock (a run begun
   under a contract with no window). The kernel releases the lock when the launcher dies, however it dies.
   The lock file is the one object of the window that a held agent can reach: no tier denies chmod, and its name follows
   from the agent's identity, so another agent of the same account could take its mode and refuse every later start of this
   one. `tego run` therefore restores the owner's read and write on every `.window-*.lock` in the ledger root at its start,
   as it does on the run directories (`restoreRunDirs`); a lock that still cannot be opened (a mode taken again between the
   restore and the open, or a file of another account's) is refused as the lock, with the `chmod` that fixes it
   (`budgetwindow.ErrLockFile`), not with the advice for a damaged ledger.
6. **A run that never ended counts to its last line.** A launcher killed with its agent leaves a ledger with no
   `run_end` and no `chain.log` line. Its chain is verified to its last line, and it is counted. What it spent after the
   last line it wrote (lines still in the launcher's queue go with it, as `tego run` already says) is not in any record
   and is not counted: this is the one way the count can be low, and it is stated, not hidden.
7. **The window is one window, not one per run.** The watcher keeps spend in one-minute buckets (`limits/window.go`):
   the earlier runs' responses are priced with this run's price table, as its own are, so one price list reads the whole
   window; the sum of the buckets still inside the span is what is compared with the ceiling, on every response. Spend
   leaves the window a minute late at most, never early. The ceiling is crossed the same way a per-run one is: one
   `limit` line, `which` tokens or cost_usd, `value` the window's total, `ceiling` the contract's, then `run_end
   reason=limit`, exit 124.
8. **The ledger says the run counted, and a verifier can recompute it.** `run_start.limits.window` records the span
   (optional, a duration, present exactly when the contract set one; added to record revision 41, which no release
   carries, so the revision does not move and the field is in the record spec, its tests and the frozen field list).
   Right after `run_start` the run writes `gap what=limits why=window-carried count=N`, N the earlier runs it read (not
   written when N is 0), and the gaps of decision 3 when they apply. The amounts are not written: they are in the earlier
   runs' ledgers, and a number copied into this one would be a second place for it. Instead the record spec ("A budget over
   a window", `spec/record/v1/README.md`) says how to recompute the `limit` line's `value` from the records alone: the
   agent's identity from `contract_source`, the window from `limits.window`, every other run of that agent in the ledger
   root, every response placed in its minute and counted while its minute ends after the time of the limit line minus the
   window. Tokens are `input + output`; the cost uses the run's price table, applied to every response as `tego measure`
   applies it, an unlisted model at the table's highest prices. The record carries no price table (nor does any record),
   so a verifier that lacks the table recomputes tokens exactly and cost to the table it has; the repricing limit below
   says why a later change of table moves the cost. A test (`TestTheCarriedCountIsRecomputableFromTheRecords`) recomputes a
   run's limit value with a verifier that shares no code with the launcher's reading.
9. **The clock.** Spend is placed in the window by the wall time its ledger line was stamped with (it has to span
   restarts and reboots, which the monotonic clock does not). A run's *own* spend is placed by wall time at its start
   plus the monotonic time since, so an NTP or administrator step in mid-run neither ages it out nor adds to it. A
   line stamped after this run's start (the clock was set back) counts as spent now and leaves the window a span after
   the run's start, so a clock set back days cannot hold an agent down for days. A clock set forward past the window
   forgives spend; setting it needs root and is stated below.
10. **Retention must cover the window.** `tego gc` removes ended runs older than `retention`; a removed run's spend is gone.
    A run whose `limits.window` is longer than the machine's `retention` is refused (`[budget-window]`, fix: raise the
    retention or shorten the window), so the count never falls through the ordinary removal.

## Options considered

- A counter file or a per-agent state record, updated by each run: a second place for the number to live, to be
  corrupted, forgotten at a restore and rewritten by anything that reaches it; and it would need its own proof of
  integrity, which the ledger already has. Rejected.
- A new `run_start` field carrying the number counted at the start: the number would be the launcher's claim, not a
  proof, and it needs a record revision, which this design does not.
- Carrying the number through the unit (`Environment=` set by a wrapper script): the wrapper becomes the source.
  Rejected.
- Refusing no run but counting what is readable and noting the rest in a gap: the cap would depend on the ledger being
  intact, which is what an agent that wanted a larger cap would attack. Rejected (3).
- Cutting an unanchored ended run on its own `run_end` stamp when it is old, or refusing it until `tego gc` removes it,
  or a command that marks it acknowledged: the first needs an anchor to be a proof, the second destroyed evidence for days,
  and the third is a new command, a state file and a way for an agent's operator to forgive a count by habit. Counting the
  verified chain and saying so is the one that keeps the evidence and the count (3).
- Skipping, not refusing, a run of this agent that does not verify, with a gap: the count would depend on the agent not
  being able to damage a ledger, which is the attack. Rejected (3).
- Counting a live sibling's spend so far: its spend grows after the count, so the count is stale at once. Rejected for
  the lock (5).

## Stated limits

- A run's own watcher saw spend its ledger may not hold: a response the pipeline could not write (a `gap` says so) or
  lines lost with a killed launcher (6). The next run cannot count what no record holds.
- Runs removed by `tego gc --keep` shorter than the window, or by a person, are gone with their spend; only the
  machine's own retention is checked (10).
- A ledger root a person can write to is not defended against that person: the chain anchors protect a ledger from
  edits that leave `chain.log` alone, as everywhere else in Tego. A held run cannot write the ledger root or `~/.tego`
  (the tiers do not grant it, and tego's own directory is refused to read as well), so it cannot delete, rename, truncate
  or edit an earlier ledger or `chain.log`; the guest test shows it at each tier. What it can do is chmod a
  ledger it knows the path of, or an agent's window lock, whose name follows from the agent's identity (no tier denies chmod),
  which `tego run` restores at its start and the reader refuses, and
  it can set a file's date, which the count never reads. **A record-only run (`--observe`, or a tier that holds nothing
  back) can reach its own records, so there the count is not protected, and a window is refused there** (`[budget-window]`):
  a cap the agent could lower with `rm` is not offered. Whoever can write the ledger root can also delete or empty a run's
  ledger or rewrite its first line, and the run is then not counted, whether or not it is said (decision 3): that is the
  limit of every record Tego keeps, and the tiers are what hold it.
- A forward step of the wall clock by more than the window forgives the spend; it needs root.
- Prices come from the price table of the run that reads the window: a changed table reprices earlier spend. A model
  the table does not list is charged at the table's highest prices under a cost ceiling, as in a single run (R2).
- **What a start costs, and its bound.** Verifying costs one read of each of this agent's ledgers that were not proved to
  end before the window, at the start of every run, and the read is bounded: the events files of the runs read whole may
  hold at most 512 MiB together (`budgetwindow.MaxReadBytes`): one minute at the measured rate for ordinary lines (about 9 MB a second), two when every line is a model response (about 4.5 MB a second), and a start past it is
  refused (`[budget-window]`, fix: `record: summary` or a shorter window), not slowed without end. Per-run ceilings
  (`record.max_run_bytes`) and the 200,000-minute bound on the carried entries bound the rest. Everything else of the
  root costs one open of a run's first line (another agent's run: that line and nothing more), or one open, one tail read
  and one digest (an anchored ended run), and one pass over `chain.log`. For 10,000 runs of other agents that is seconds.
  The rest of this item is the measurement behind the bound: verifying costs one read of each of this agent's ledgers
  written inside the window, at the start of every run. Measured
  here on a synthetic ledger of 100,000 model responses (45 MB, every line a response, the worst case for the count):
  9.9 s, of which the chain check is 4.8 s (about 50 microseconds a line) and decoding the responses the rest. A ledger
  of other lines costs the check alone, so `record: full` at the measured 145 MB an hour is about 16 seconds of reading
  for each hour of ledger in the window, about 6 minutes for a day: an agent with a window of a day should run under
  `record: summary`, the default. Ledgers of
  other agents cost one line, and a ledger that ended before the window began costs one read of its last line and one
  digest. That proof is the run's `run_end`: its own digest is the head `chain.log` anchors for the run, so its stamp is
  the launcher's. The file's modification time is never used: the agent runs as the ledgers' owner and could set it to any
  date (reviewed 2026-11-24; the first build cut on it and a backdated ledger counted 0). A run with no `run_end`, or whose
  last line is not the anchored head, is read and checked whole, so a lost run older than the window is read at every start
  until `tego gc` removes it. A run that waits on
  this is waiting before `run_start`, with no agent process.
- A restart into a window that is already full is ended at its first model response (124), not before: the agent starts,
  and a model call is what the count is charged with. A unit with `Restart=on-failure` restarts it every `RestartSec`
  and stops when `StartLimitBurst` is spent, so a full window leaves the unit failed until someone runs `systemctl
  --user reset-failed` after the window has room. Refusing the start instead would be exit 125, which the unit's
  `RestartPreventExitStatus` never restarts, so the agent would stay down for good; ending at the first response keeps
  the choice with the unit's own restart policy.
- `tego adopt` meters no budget, so it has no window (ADR 0055).

## Proof

`internal/runtime/limits/window_test.go` (the arithmetic and the clock), `internal/runtime/budgetwindow/read_test.go`
(identity, window edge, tamper, truncation, missing anchor, lost run, live run, lock), `internal/runtime/window_test.go`
(a restart on real ledgers is ended at the window's ceiling and writes its gap; a restarted run a day later starts at
zero; an edited ledger, a missing `chain.log` line, a second run at once, a short retention and a contract with no name
are each refused), and `pkg/spec/agent/limitswindow_test.go` (the key). Each refusal and the ceiling were seen failing
with the check removed.

The second review's points each have a test that failed on the earlier code and passes now:
`TestReadDoesNotCountAnotherProjectsAgentOfTheSameName` and `TestTwoProjectsWithOneAgentNameRunSideBySide` (identity),
`TestReadAnEndedRunWithNoAnchorIsCountedAndSaid` and `TestAMissingAnchorCountsTheRunAndSaysSo` (an unanchored run), with
`TestReadAnUnanchoredRunThatDoesNotVerifyIsStillRefused` and `TestReadAnAnchorThatCannotBeReadIsRefused` holding the other
side; `TestReadAnotherAgentsDamagedRecordNeverBlocks`, `TestAnotherAgentsDamagedRunDoesNotRefuseTheStart`,
`TestReadARunWithNoReadableFirstLineIsLeftOutAndSaid`, `TestReadAnUnreadableRecordOfOurOwnAccountIsRefusedByName` and
`TestReadNamesThisAgentsDamagedRunAsItsOwn` (whose record can refuse); `TestLimitsWindow` (the code `limit-window-range`);
`TestAWindowIsRefusedWhereTheAgentCanReachItsRecords` (record-only run); `TestTheCarriedCountIsRecomputableFromTheRecords` and
`TestRunStartRecordsTheWindow` (the verifier); `TestReadRefusesALedgerPastTheReadBudget` (the bound); and
`TestReadAnAgentsAttemptsOnItsOwnRecord`, one row for each thing an agent could do to an earlier record. The third review's point, a window lock whose mode a held agent took, is
`TestRestoreOwnStateGivesBackAWindowLock` (restored at the start, a lookalike name left alone, the agent then starts),
`TestALockThatCannotBeOpenedIsNotALedgerFault` and `TestALockThatCannotBeOpenedIsErrLockFile` (the refusal names the lock),
and `TestTheLockIsNamedAsIsLockNameSays` (the restore finds the lock by the name Acquire makes). The kernel half
(an agent held at tiers landlock, cgroup and bpflsm denied the removal, rename and edit of an earlier ledger and of
`chain.log`, a restarted run stopped at a full window, as an ordinary user and as root) is a guest row.
