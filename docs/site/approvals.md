---
title: Approvals
description: "Make an agent's action wait for a person: ask rules in the rules file, answering on the dashboard or with tego approve and tego deny, timeouts and limits."
summary: "Make an action wait until a person allows or refuses it."
section: Core concepts
order: 5
---

An `ask` rule holds an action until a person allows or refuses it. The agent's system call waits while the question is open. If nobody answers before the timeout, the action is refused. You answer on the dashboard's Approvals page or with `tego approve` and `tego deny`.

## What can wait for a person

| Rule | What waits | Levels |
|---|---|---|
| `fs.ask` | Writes, creates, renames and removals under a path | Basic, Plus, Max |
| `fs.ask_read` | Reads of a file or folder | Basic only |
| `net.ask` | Connections to a `host:port` | Basic, Plus, Max |
| `mcp[].tools.ask` | Calls of a named MCP tool (a tool the agent calls through the Model Context Protocol) | Basic, Plus, Max |

`exec.ask` never asks. Every program it matches is refused at every level, and `tego rules check` warns about it. Use `exec.allow` or `exec.deny` for programs.

`fs.ask_read` works only at Basic. A rules file with `fs.ask_read` is refused when its session would run at Plus or Max. Add `tier: landlock` to keep the session at Basic. [Protection levels](/docs/tiers/) explains the levels. On Debian 12 and 13, Basic refuses read approvals instead: see [Supported systems](/docs/supported-systems/#distributions).

An `fs.ask` path inside an `fs.write` folder is never asked: the write rule already allows it. Keep held folders outside your write folders.

## Write an ask rule

```yaml
fs:
  write: ["./work/"]
  ask: ["./held/"]
net:
  ask: ["api.example.com:443"]
ask:
  timeout: 10m
```

`fs.ask` and `fs.ask_read` take literal paths, with no `*` or `?`. `net.ask` entries need a port. The `ask:` section sets how waiting works:

| Field | Meaning | Default |
|---|---|---|
| `ask.timeout` | How long a question waits. At most `1h`. | `5m` (`4m` with `ask.hold: request`) |
| `ask.on_timeout` | `refuse` refuses this one action. `refuse_always` also refuses the same action, rule and target at once for the rest of the session. | `refuse` |
| `ask.max_pending` | How many questions can wait at once, 1 to 64. A new question past the limit is refused at once. | `64` |

[Rules file fields](/docs/rules-reference/) lists every `ask` field.

## Where the question shows

When a rules file has an ask rule, `tego run` prints one line before the agent starts. It names the session and the commands that answer. At Basic, when the session was started without `sudo`, a desktop notice also says when a question waits.

On the dashboard, the Approvals page lists each waiting question with what the agent asked for, the rule that asked and how long it waits. The Overview also says something needs you. [Dashboard](/docs/dashboard/) shows how to open it.

Which notices Tego gives is a machine setting, `ask.notify`. See [Machine settings](/docs/machine-settings/).

## Answer on the dashboard

- **Allow once**: this action goes ahead.
- **Deny**: this action is refused.
- **More choices**, then **Allow for this run** or **Deny for this run**: the answer also stands for later requests for the same action, rule and target until the session ends.

The rules file does not change. After a Deny, the action's line in the session offers **Never allow**, which adds a rule that refuses it from the next session on.

## Answer from a terminal

Answer from a terminal outside the session:

```sh
tego ask
tego approve <ask_id>
tego deny <ask_id>
```

`tego ask` lists the questions waiting in every running session, each with its ask ID. `tego ask <session>` lists one session's questions. `tego approve` and `tego deny` also take the session first: `tego approve <session> <ask_id>`.

Add `--always` to make the answer stand for the same action, rule and target until the session ends:

```sh
tego deny <ask_id> --always
```

A held file open can also be answered with another file. The agent's open then gets that file in place of the one it asked for:

```sh
tego alternate <ask_id> --file <path>
```

## Who can answer

The user who started the session can answer, and so can root. A process inside the session cannot answer its own questions, from the terminal or the dashboard.

An administrator can set `local_roles: owner_only` in `/etc/tego/config.yaml`. Sessions started after that take answers from root only. Sessions already running keep the old rule until they end. [Machine settings](/docs/machine-settings/) covers it.

## With nobody watching

A held action waits the full `ask.timeout`, then it is refused and recorded as a timeout. With `on_timeout: refuse`, the agent's next try waits again for the full timeout. For an agent that runs unattended, keep ask rules for the few actions a person must decide, and set `ask.on_timeout: refuse_always` or put the rest in `fs.write`, `net.allow` or a deny rule. [Services](/docs/services/) covers agents that run with nobody watching.

## Next steps

- [Dashboard](/docs/dashboard/): answer questions on the Approvals page.
- [Refusals](/docs/refusals/): what the agent sees when an answer is no.
- [Rules file fields](/docs/rules-reference/#questions-for-a-person-ask): every `ask` field.
- [Session control](/docs/session-control/): block, pause or stop a running session.
