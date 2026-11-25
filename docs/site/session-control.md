---
title: Session control
description: "Stop, pause and resume a running Tego session, block a program, host or path while it runs, and lift or grant fence entries on an Adjustable session."
summary: "Stop, pause, block and loosen a session while it runs."
section: Advanced usage
order: 5
---

You control a running session from any terminal outside it. `tego session stop`, `pause` and `resume` act on the whole session. `tego block` refuses one more program, host or path, now. On an [Adjustable](/docs/live-changes/) session, `tego lift` and `tego grant` allow a fence entry and `tego restore` refuses it again. The dashboard has the same controls ([Dashboard](/docs/dashboard/)).

Every command takes the session's name (such as `claude-code-a1b2`) or its id. List the sessions:

```
tego session list
```

## Stop a session

```
tego session stop claude-code-a1b2
tego session stop --agent claude-code
```

Tego sends the agent `SIGTERM` and waits for the machine's `stop_grace` ([Machine settings](/docs/machine-settings/)). Every process still left in the session when it runs out is killed. `--grace 30s` sets a different wait for this stop. `--agent <name>` stops every running session of that agent (the `name:` in its rules file).

Pressing Ctrl-C in the session's terminal, or closing it, starts the same countdown. The session's exit code says how it ended: see [Exit codes](/docs/exit-codes/).

## Pause and resume

```
tego session pause claude-code-a1b2
tego session resume claude-code-a1b2
```

Pause freezes every process of the session where it stands: none runs or handles a signal until you resume it. While paused, the `stall_after` limit does not count; the `wall` limit and the timeout of a waiting [approval](/docs/approvals/) keep counting. Stopping a paused session ends it as quickly as a running one.

## Block something now

```
tego block claude-code-a1b2 net example.com:443
tego block claude-code-a1b2 exec /usr/bin/curl --for 2h
tego block claude-code-a1b2 write ./src/ --until 17:00
```

The session's launcher puts a block in force within about a second. From then on the agent gets a permission error and the record shows a refused line with the rule `live.block[<kind>:<value>]`. A block only makes the session stricter; it never allows anything.

| Kind | Value | What it refuses |
|---|---|---|
| `exec` | An absolute path, a folder ending in `/`, or a bare name such as `curl` | Starting that program, every program in that folder, or every program of that name |
| `net` | `host[:port]`, `IP[:port]`, a unix socket path, or `@name` for an abstract socket | Connections to it. No port means every port. |
| `path` | A path | Reads and changes of it and everything beneath it |
| `read` | A path | Reads only, plus a rename or hard link that would give the file a name outside the block |
| `write` | A path | Changes only: writes, creates, deletes, renames, links, `mkdir` |

| Flag | Meaning |
|---|---|
| `--for <duration>` | The block ends after this long: `45m`, `72h`, `3d`, `1d12h`, `7w` |
| `--until <time>` | The block ends at this time: `17:00`, `tomorrow 09:00`, `Fri 17:00`, `2026-11-14 17:00` |

A time limit is between 1 minute and 400 days. With neither flag, the block lasts the rest of the session.

List the session's blocks and their state:

```
tego block --list claude-code-a1b2
```

Remove a block, back to what the rules file allows:

```
tego unblock claude-code-a1b2 net example.com:443
```

`tego unblock` with `--for` or `--until` removes the block for that long, then it refuses again. What the rules file refuses stays refused.

A block on a `tego watch` session is recorded on each matching line but refuses nothing, since that session enforces no rules.

## Loosen an Adjustable session

On an Adjustable session, each fence entry starts refused. Allow one:

```
sudo "$(command -v tego)" lift claude-code-a1b2 read ~/billing-exports --for 15m
sudo "$(command -v tego)" grant claude-code-a1b2 net api.stripe.com:443 --note "refund job"
```

`lift` is for an entry that names one of the rules file's refusals; `grant` is for an entry that is new access. Both take `--for`, `--until`, `--note <text>` (up to 200 bytes, kept in the record) and `--yes`. At a terminal they ask you to type the word `lift` or `grant`; without a terminal, pass `--yes`. Refuse the entry again:

```
sudo "$(command -v tego)" restore claude-code-a1b2 read ~/billing-exports
```

A Locked session refuses `lift` and `grant` with `[locked]`, and an entry outside the fence is refused with `[outside-fence]`. [Live changes](/docs/live-changes/) explains the fence.

## Sessions started with sudo

A session at Plus or Max is started with `sudo`, and its folder belongs to root until it ends. Changing it while it runs (stop, pause, block, unblock, lift, grant, restore) needs `sudo` too. Without it the command exits 1 with `[root-run]` and says to repeat it as root.

## What a session can do to itself

From inside a session, `tego block` and `tego restore` can name only that same session: an agent can make its own session stricter, never another one. `unblock`, `lift` and `grant` are refused from inside any session.

## Next steps

- [Live changes](/docs/live-changes/): Locked and Adjustable sessions
- [Approvals](/docs/approvals/): answer an action that waits for a person
- [Exit codes](/docs/exit-codes/): how a stopped session ends
- [Commands](/docs/commands/): every flag
