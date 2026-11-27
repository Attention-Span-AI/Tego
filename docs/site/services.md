---
title: Services
description: "Keep an agent running under Tego as a systemd user unit: tego run --service, the tego-agent@ template, restarts, stops with exit 143 and asks nobody answers."
summary: "Run an agent all the time as a systemd user unit."
section: Production
order: 2
---

A systemd user unit keeps an agent running under Tego and restarts it when it fails. Tego ships a unit template, [`examples/systemd/tego-agent@.service`](https://github.com/Attention-Span-AI/Tego/blob/main/examples/systemd/tego-agent@.service). Each instance runs one agent from your rules registry, and each restart is a new session with its own record.

## Before you start

- The account that runs the agent has Tego installed in `~/.local/bin` and a running user manager. For an account nobody logs in to, follow [Servers and CI runners](/docs/servers-and-ci-runners/#run-as-a-service-account) first.
- The agent's rules file is saved by name in `~/.config/tego/agents/<name>.yaml`, with `name: <name>` inside. `tego rules learn <session> --save <name>` writes it there ([Learning rules](/docs/learning-rules/)).
- `tego run <name>` works from a terminal.

## Install the unit

The instance name is the agent's name. For an agent named `retriever`:

```sh
cp tego-agent@.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now tego-agent@retriever
```

The unit starts `tego run --service retriever` from your home folder, so relative paths in the rules file resolve against `~`. A user manager does not read your shell profile, so the unit sets `PATH` itself. The agent sees it only when the rules file lists `PATH` in `env.pass`.

A user unit runs only while the user manager runs. On a machine where you are not logged in all the time, turn on linger once:

```sh
sudo loginctl enable-linger "$USER"
```

## How the unit treats each exit

The unit's restart rules follow `tego run`'s [exit codes](/docs/exit-codes/):

| Exit | The unit |
|---|---|
| 143: you stopped it with `tego session stop` or `systemctl --user stop` | Stays stopped, counted as success. |
| 125 | Stays stopped. A restart would fail the same way. |
| 0: the agent finished | Stays stopped. |
| Any other code, 124 and 137 included | Restarts after 10 seconds, at most 12 times in 30 minutes. |

`--service` makes a stop you asked for exit 143 even when the agent ignores SIGTERM and Tego kills it after `stop_grace`. The record still notes that the stop escalated. Without `--service`, that case exits 137 and the unit restarts the agent.

## Stop, restart and check the agent

Stop every running session of the agent by name:

```sh
tego session stop --agent retriever
```

The unit stays inactive until you start it again with `systemctl --user start tego-agent@retriever`. To see what each session did, use `tego session list` and `tego session show <session>` ([Session control](/docs/session-control/)).

For a fresh session once a day, enable the restart timer that ships beside the unit:

```sh
cp tego-agent-restart@.service tego-agent-restart@.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now tego-agent-restart@retriever.timer
```

Once a day, at midnight, it stops the agent's session and starts a new one. It leaves an agent you stopped as it is. A restart starts from the rules file alone: a `tego session pause` and every `tego block` from the old session are gone. A block that must outlast the restart belongs in the rules file.

## Keep the disk in check

A session's record grows as long as the session runs. Two machine settings bound it ([Machine settings](/docs/machine-settings/)):

- `record.max_run_bytes` ends the session as a limit ([Exit codes](/docs/exit-codes/)) when its record reaches that size. The unit then restarts the agent on a new record.
- `retention` and `gc_interval` remove old ended sessions. On a machine where no session starts for days, enable `tego-gc.timer` from `examples/systemd/`, which runs `tego gc` once a day.

## Plan memory for Plus and Max sessions

Each Plus or Max session's launcher peaks near 70 MB of memory and shares about 28 MB with the kernel. Plan about 3 GB of memory for 32 sessions at once. A cold start at these levels takes 9 to 18 seconds; Tego prints a `[startup-wait]` note after about a second.

## Questions with nobody watching

In a service nobody answers, so each held action waits for `ask.timeout` and is refused. [Approvals](/docs/approvals/#with-nobody-watching) shows how to make retries fail at once.

## Next steps

- [Approvals](/docs/approvals/): answer held actions from the dashboard or the terminal.
- [Budgets](/docs/budgets/): cap tokens and cost for an agent nobody watches.
- [Session control](/docs/session-control/): block, pause or stop a running session.
- [Exit codes](/docs/exit-codes/): every code `tego run` returns.
