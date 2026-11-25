---
title: Live changes
description: "Choose whether a running Tego session can only get stricter (Locked, the default) or can also loosen inside a fence you name in advance (Adjustable)."
summary: "Locked and Adjustable: what can change while a session runs."
section: Advanced usage
order: 4
---

A session runs in one of two modes, set by `live.mode` in its rules file. **Locked**, the default, fixes the file, program and network rules when the session starts: you can make it stricter while it runs, and you loosen it from the next session. **Adjustable** also lets you loosen it while it runs, but only for entries you listed in advance in a fence, and only at Plus or Max.

## What can change during a session

| Change | Locked | Adjustable |
|---|---|---|
| Block a program, host or path; pause; stop | Yes | Yes |
| Remove a block | Yes | Yes |
| Allow something the rules refuse | No: edit the rules file, it applies from the next session | Yes, for fence entries only (lift or grant), and refuse it again (restore) |
| Turn on an MCP tool or switch a model route past the rules file | No, refused `[locked]` | Yes |
| Change the mode or the fence | From the next session | From the next session |
| Protection levels | All | Plus and Max |

The commands are on [Session control](/docs/session-control/), which also says [what a session can do to itself](/docs/session-control/#what-a-session-can-do-to-itself).

## Choose a mode

Locked needs nothing. A rules file with no `live:` key, or with `live: {mode: locked}`, is Locked.

Adjustable needs a fence: the list of what you will be able to allow while the session runs. Every fence entry is refused when the session starts.

```yaml
fs:
  deny_read: [~/billing-exports]   # the rules refuse it...
exec:
  allow: [/usr/bin/bash, /usr/bin/git]   # a read entry needs an exec.allow list
net:
  allow: [api.anthropic.com:443]         # a net entry needs a net: section
live:
  mode: adjustable
  fence:
    read: [~/billing-exports]      # ...and you can lift that refusal while it runs
    net:  [api.stripe.com:443]     # new access you can grant
    exec: [/usr/bin/psql]
```

To start a new rules file in Adjustable mode:

```
tego rules create --live-mode adjustable
```

It writes `agent.yaml` with an empty fence to fill in. `--live-mode locked` is the default. `tego rules check` prints the fence and refuses an entry it cannot hold.

## What a fence entry can be

The fence holds at most 64 entries, of three kinds:

| Kind | Value | How it holds |
|---|---|---|
| `read` | A path that matches one of your `fs.deny_read` entries exactly | Exact. While the fence has a `read` entry, Tego holds every read open of the session and checks the file it opened, so a swapped link does not get through. |
| `net` | `host:port` or `IP:port`, TCP only | Exact. Tego makes the connection for the agent. UDP to the destination stays refused, lifted or not. |
| `exec` | An absolute program path | Best effort. Tego decides on the program's name and file, so a copy under another name in a folder the agent writes is not covered. |

There is no write kind. `tego rules check` refuses a fence entry that:

- the rules already allow
- is a unix socket or has no port
- reaches Tego's own files or one of the [built-in refusals](/docs/built-in-refusals/)
- names a program inside a folder the agent writes

A `live:` key in a preset or profile you extend is refused: only your own rules file picks its mode.

## Why Adjustable needs Plus or Max

At Plus and Max the kernel holds the session to the rules plus the fence, and Tego's own layer refuses each fence entry until you lift it. Adjustable is refused at Basic, and `tego run` refuses an Adjustable session whose level comes out as Basic. Plus and Max need root, so an Adjustable session is started with `sudo` ([changing it while it runs](/docs/session-control/#sessions-started-with-sudo)).

## Which mode to pick

Locked is the stronger promise: the session is never looser than its rules file while it runs. Adjustable is weaker by exactly the fence: what you list there is held back by Tego, not by the kernel, until you lift it. Pick Adjustable for an agent that runs for days and whose access you expect to change. Keep Locked for everything else.

A time limit on a lift does not take back what the agent already got: data it read, files it still has open and connections it already made stay. It stops new access only.

## Next steps

- [Session control](/docs/session-control/): block, lift, grant and restore commands
- [Protection levels](/docs/tiers/): what Plus and Max need
- [Rules file fields](/docs/rules-reference/): `live.mode` and `live.fence`
