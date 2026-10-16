# ADR 0054: govern any agent as a black box: the watch launch path, standing approvals, and a staged resident watcher

Status: **accepted 2026-10-06**; the launch path (`tego watch`), standing approvals (`approve|deny --always`), learn mode (`tego learn`), detection (`tego agents`) and adoption of an already-running agent (stage 2, ADR 0055) are built and run; a resident service (stage 3) is not built.

Amended in part by ADR 0044 (accepted 2026-10-16, not built): standing answers gain the `exec` hold, keyed on the exact facts, refused for a program the agent can write, with a deny-side `--command` pattern.
Amended in part by ADR 0055: stage 2 holds no network rule on an adopted process.

Written and built as a POC on 2026-10-06, with two independent security reviews of the approval work. Amends nothing
(ADR 0042 stands; see (4)).

## Goal

Run any agent (Claude Code, Codex, a custom one) as a black box, fully interactive and
unattended for hours; enforce what it may touch (files, addresses, ports, programs, resources); let a person pause it,
answer, or decide once for the rest of the run; keep a full log of what it did; watching agents the way an anti-cheat watches a game, without the agent having to be known in advance.

## What was true before this work

Only `claude -p` had a passing end-to-end test, at tier 1 against a local stand-in for the model. Whether a full-screen
interactive agent worked under tego at all was untested, and approvals were all-or-nothing per request.

## Decision

1. **The launch path is the primary path (built).** `tego watch [--boundary <contract>] -- <command>` runs any command
   through `tego run`'s own launch path. With no boundary it is a record-only run under a generated contract that
   names only the program (a full record, no rule that refuses) and says so before it starts, including what the fixed
   syscall guards still refuse and what is not recorded; with one it is `tego run`
   with the command given on the line. Tego never needs to know what the command is; the only agent-specific data
   anywhere is optional signatures (4). Why the launch path is primary: only the launcher can install the seccomp filter
   and Landlock before the agent's first instruction, set its environment (so model traffic reaches the forwarder), and
   know exactly which processes are the agent.
2. **Standing approvals (built).** `tego approve --always` and `tego deny --always` make an answer stand for the rest of
   the run, for the same operation, contract rule and exact target and no other, for a file open or a TCP connect only.
   A scored gate request and a `first_write` or `request` hold are never remembered (their approval is bound to the score
   or the bytes the person saw). At most 256 stand; they end with the run; each automatic answer is its own `ask` and
   `answer` pair in the ledger (`by: standing:<ask_id>`), so no grant or refusal is unrecorded; a ledger that refuses a line
   refuses the operation; and a timeout still refuses. A standing answer takes effect only once the human's own answer
   line is in the ledger and nothing replaced it (a cancelled, closed or unrecorded `--always` answers once and stands
   for nothing, and the CLI says so); a second `--always` for a key whose first is still being recorded is refused
   (`standing-busy`) with the request still pending; a standing answer is refused when its owner is cancelled while
   its two lines are written; and standing answers count against the cap of 64 open asks the ledger allows while
   their lines are written. A file's key is its path, not how it is opened. **Nobody answering is never a yes**: `ask.timeout` is at most one
   hour, and no setting turns silence into approval. Long unattended runs rely on the contract's own rules and a few
   `--always` answers, not on waiting.
3. **A resident watcher, in stages (staged; only stage 1 started).** It exists for an agent that was started outside
   tego, in any terminal or IDE. It cannot do what the launcher does: a running process cannot be given a seccomp filter
   or Landlock, its environment cannot be changed, and a few instructions run before it is noticed.
   - Stage 1, **detection only**: a foreground command (`tego agents`, root, `CAP_NET_ADMIN`) reads the kernel's
     process-start notifications, matches editable signatures, follows an agent's descendants, and reports sightings,
     including whether the agent runs inside a governed tego run. It signals, moves and blocks nothing.
   - Stage 2, **adoption**, decided only after stage 1's evidence: put the matched agent in a fresh cgroup of its own (it
     shares its cgroup with the user's terminal, so adopting that one would govern unrelated processes) and attach the
     root tiers' programs, so that from then on its files, programs and connections are recorded and decided in the kernel.
     Whether tego can move a running process into a run's cgroup is not yet established and is the first thing stage 2
     must settle. (Settled and built: ADR 0055.)
   - Stage 3, a resident service (a daemon), only if a named trigger fires; see (4).
4. **Scope boundary and ADR 0042.** Tego governs agent sessions only: the processes the operator chose to govern and
   their descendants. It never monitors or controls the rest of the host, never hides from or resists root, and root can
   always see and remove its programs (host-wide control is out of scope). Host-wide or administrator-resistant control is not
   proposed. ADR 0042 says there is no daemon until a named trigger fires: stages 1 and 2 are foreground commands and
   amend nothing; stage 3 would need its own trigger and its own ADR.

## Evidence (2026-10-06)

- The real full-screen Claude Code 2.1.290 and Codex 0.159.2 run under `tego watch` on a pseudo-terminal, with window
  size, Ctrl-C and exit status; Claude Code also runs under an enforcing boundary at tier landlock
  (`test/poc/watch-demo/real-agents/README.md`).
- The demo (`test/poc/watch-demo/README.md`): with a boundary the secret read, the program and the connection are
  refused with their rules; a held write paused the agent until a person ran `approve --always`; the repeat was answered
  at once by a recorded standing answer; `deny --always` refused a retry at once; with nobody answering the write was
  refused at the timeout.
- With no boundary, Codex alone sitting at its login screen started 180 programs, cloned a repository, probed its own
  sandbox and touched the D-Bus session bus: the record is useful before any rule exists.
- A whole interactive Claude Code 2.1.290 session ran at tier landlock with no root, the model replaced by a local
  stand-in (`test/poc/interactive-claude/README.md`, 29 checks): tool use, 141 refusals each with its rule, a held write
  that paused the session until a second process approved it, an `--always` answer recorded and then applied at once,
  every model request recorded through the forwarder, and 106 reads of the real `~/.claude` refused.
- An independent security review of the standing answers found two defects, fixed with tests that fail without the
  fix: an "always" that was cancelled or never recorded still became a standing answer, and standing answers were not
  counted against the cap of open asks.

## What it does not do

It does not make a recording a cage: an unbounded run has no rule that refuses anything (tier 1's fixed syscall guards
still apply), and a process can still ask another service on the
machine (systemd --user, D-Bus, an SSH or GPG agent) to act for it outside the run. It does not read model traffic unless
the agent was launched with the forwarder's environment. It does not run or authenticate a model call without a user-supplied
key: a logged-in or API-key session with the real model, MCP servers, the IDE link and Claude Code's auto
permission mode are untested (tool use and an approval inside a live session ran offline, against a stand-in). The real Claude
Code exits at its startup check under a forwarder-only boundary (it connects directly to `api.anthropic.com`), so a
working boundary for it today allows that host directly and gives up recording its model traffic (FEATURES I2 names the
gap).

## Consequences

The launch path, standing approvals, learn mode and detection are built, and adoption is ADR 0055. Claude Code's offline
session is proven; Codex and the real-model run remain.

## Alternatives considered

- **Wrap only (today).** Misses an agent started elsewhere, and says nothing about one started outside tego.
- **Agent-side hooks and telemetry only** (Claude Code's managed settings, hooks and OpenTelemetry export, Codex's config).
  Cooperative: the agent's own code reports, and can be turned off by it or by the user; useful as a semantic layer, never as
  enforcement.
- **Kernel-module or below-kernel monitoring, or anything that resists the administrator.** Out of scope; not proposed.

## Open questions

1. Should an answer ever persist across runs? It would need a store and its own security review; this ADR says no,
   and nothing here changes that.
2. `alternate` (hand the agent a stand-in instead of the real thing): safe for a read, risky for a write or a connect.
   Designed here; not built when this ADR was accepted (FEATURES W7).
3. The one real-model run that turns "starts and stays up" into "works".

*Amended 2026-10-16 (ADR 0055):* stage 2 is built and accepted as ADR 0055: `tego adopt --pid` and the guard
`tego agents --follow --adopt --uid` move an already-running agent's own process tree into a fresh
`adopt-<run>.scope` and record it from the kernel; a boundary holds only what the decision plane decides (file and exec
rules), and **no network rule** is held on an adopted process, since a socket made before the move keeps its old cgroup
and the record could not tell which connects were governed. Stage 2's "decided in the kernel" is narrowed to that.

*Amended 2026-10-17:* the detector's scan read every
process whose `/proc/<pid>/stat` says `Z` as gone, so an agent whose main thread had exited while its other threads
ran (`pthread_exit` in `main`, no privilege needed) was never reported, nor adopted by the guard, if it did so before
the detector looked, and nothing counted it. Such a process is now read through a live thread of it under
`/proc/<pid>/task` (its program, arguments, cgroup and run id), checked to be the same task once read; a zombie
whose whole group has exited is still gone. Test: `TestScanFindsAnAgentWhoseLeaderExited`, and on the running kernel
`TestIntegrationFactsReadAnAgentWhoseLeaderExited`.

*Amended 2026-10-17:* the detector still took a
process's leader's exit event for the process's end. So an agent whose main thread exited while it was followed was
reported `agent_exited` (with the main thread's code) while it ran on, and what its threads forked was no longer
followed; and an agent the scan found with its main thread already gone was never reported ended, since the only exit
event left was its last thread's, which was skipped as a thread's: its session stayed and hid a later agent given the
pid. A process now ends with the first exit event of any task of it after which no task of it runs, read from
`/proc` once the event has been read, and its status is what its tasks' codes agree on, else unknown with a note
(ADR 0055, What was measured (e)); both paths follow an agent whose main thread exits until its last thread does.
Tests: `TestAnAgentWhoseMainThreadExitsRunsOnInItsSession`, `TestAnAgentFoundWithItsLeaderGoneEndsWithItsLastThread`,
and as root `TestIntegrationWatcherFollowsAnAgentWhoseMainThreadExits` and
`TestIntegrationWatcherEndsAnAgentFoundWithItsMainThreadGone`.

*Amended 2026-10-19:* reading `/proc` when
an exit event is handled tells the state when it is read, not when the event was sent, so an event read late ended a
process early: an agent whose worker thread exec'd a program was reported `exit=0` at its zapped main thread's exit
although the program exited 3, an exec that failed after ending the other threads left its session open (the stale
state that hid a later agent given the pid), and a thread's `exit_group(3)` read before the main thread's exit gave no
status. The detector now keeps each followed process's set of tasks that run from its events (a scan lists the tasks
of what it finds, and of everything after lost events), and the process ends at the exit that empties it; a status is
one its tasks' codes agree on, signals included (ADR 0055, What was measured (e)). Tests:
`TestTheEndIsTheEventsNotWhatProcShowsWhenTheyAreRead`, `TestAProcessThatEndsDuringAScanIsEndedByItsExit`, and as root
`TestIntegrationWatcherReportsTheStatusOfAProgramAThreadRan`.
