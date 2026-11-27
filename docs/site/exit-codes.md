---
title: Exit codes
description: "What each tego exit code means: the agent's own code, 124 for a limit, 125 when Tego refused to start, 126, 127, 137, 143, and codes of other commands."
summary: "What each exit code from tego run and the other commands means."
section: Reference
group: Command line
order: 2
---

`tego run` exits with the agent's own exit code, unless Tego ended the session or never started it. Then it uses one of the codes below. Other commands use a short, separate set. The codes of the installer are on [Install](/docs/install/).

## When an agent runs (`tego run`)

| Code | Meaning |
|---|---|
| The agent's code (0-255) | The agent exited by itself. Tego passes its code through. |
| 124 | A limit ended the session: `wall`, `stall_after`, `repeats`, `tokens` or `cost_usd` from the rules file, or the machine's record size limit (`record.max_run_bytes`). See [Budgets](/docs/budgets/). |
| 125 | Tego did not start the agent, or lost it. Causes: the rules file is invalid, the protection level is not available, a budget has nothing to count it, the machine settings are untrusted. The message ends with a code in brackets, such as `[tier-unavailable]` or `[budget-unmetered]`. |
| 126 | The command was found but could not run: not executable, or the rules do not allow it. |
| 127 | The command was not found. |
| 128+n | The agent died from signal n. |
| 137 | Tego killed the session: a stop did not finish within its grace time, or the agent hit the `memory` or `pids` limit. |
| 143 | `tego session stop`, or a SIGTERM sent to `tego run`, ended the session in time. With `tego run --service`, every stop you asked for exits 143, including one that had to kill. |

A refused program inside the session does not end it. The agent sees the refusal as an error, and [Refusals](/docs/refusals/) explains what it gets.

## Other commands

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | A finding. Examples: `tego rules check` found an error, `tego events --verify` or `tego session show --verify` found a broken chain, `tego drift` found drift, `tego status` found a stalled or lost session, `tego machine check` found no level this machine can enforce, a live change was refused. |
| 2 | Usage error: an unknown command or verb, wrong arguments, or `tego start` run outside a terminal. |
| 3 | `tego scan --check` could not read some of your own program files and found nothing else. |
| 125 | Tego's own error: the command could not do its work. |
| 211 | `tego machine check --require <level>`: this machine is below that level. `tego run` never uses 211. |

## Machine test (`tego machine test`)

| Code | Meaning |
|---|---|
| 0 | Every test action was refused. |
| 1 | An action got through or was not recorded. |
| 2 | Usage error. |
| 125 | A check could not be judged, or the test could not run. |

[Self-check](/docs/self-check/) explains the report.

## Next steps

- [Troubleshooting](/docs/troubleshooting/): fixes for exit 125 and other errors.
- [Commands](/docs/commands/): every command and its flags.
- [Refusals](/docs/refusals/): what the agent sees when Tego refuses an action.
