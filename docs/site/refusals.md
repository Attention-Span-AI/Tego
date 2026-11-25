---
title: Refusals
description: "What an agent sees when Tego refuses an action: the system error, exit status 126 for a program, the Claude Code hook message and the $TEGO_REASON file."
summary: "What the agent sees when Tego refuses an action, and how it can learn why."
section: Core concepts
order: 4
---

When Tego refuses an action, the agent's system call fails with an ordinary error, such as "permission denied". The error alone does not say that a rule decided. Whether the agent also learns why depends on the agent and on how you started the session: Claude Code gets a message from Tego, every other agent can read a file, and sessions started with `sudo` get neither. Every refusal also goes into the session's record.

## The error the agent gets

| What was refused | What the agent sees |
|---|---|
| A file open, write or change | `EACCES` (permission denied) at every level. At Plus on a machine where Plus runs without its kernel hooks, Tego's kernel file listener (fanotify) refuses instead, with `EPERM` (operation not permitted). |
| A program start | `EACCES` at every level. A shell reports exit status 126 for the command. |
| A network connection | `EACCES` at every level. At Plus and Max, a datagram sent without a connection, to a destination the rules don't allow, fails with `EPERM`. |
| An MCP tool call | A JSON-RPC error with a readable message. See [MCP tool refusals](#mcp-tool-refusals). |

If Tego refuses the agent's own command, the one you gave `tego run`, the agent never starts and `tego run` exits with code 126. [Exit codes](/docs/exit-codes/) lists every code.

Tego never rewrites the agent's action or answers in its place.

## Who is told why

| Session | Claude Code | Any other agent or script |
|---|---|---|
| Started without `sudo` (Basic) | A hook message in its conversation, and `$TEGO_REASON` | `$TEGO_REASON`, if it reads it |
| Started with `sudo` (Plus or Max) | Neither | Neither |

Only Claude Code has a hook. Tego installs it for the session and Claude Code shows Claude a short note that names each refused action and the rule. [Claude Code](/docs/claude-code/) covers the hook and what switches it off.

Codex and every other agent get the error and nothing more, unless the agent or a wrapper script reads `$TEGO_REASON`. Nothing puts the reason into the model's context for them. [Codex](/docs/codex/) has the details for Codex.

A session started with `sudo` has no runtime folder for the agent, so Tego sets no `$TEGO_REASON` and installs no hook. The record still holds every refusal.

## The reason file

In a session started without `sudo`, the environment variable `TEGO_REASON` holds the path of a JSON file, `last-refusal.json`. Any process in the session can read it. It holds:

- the latest refusal at the top level: what was refused, the reason code, the rule and one sentence that explains it
- `refusals`: how many refusals the session has had
- `recent`: the newest 32 refusals, oldest first

```sh
cat "$TEGO_REASON"
```

Tego rewrites the file at most every 10 milliseconds, after the refusal reaches the record. A script that reads it right after a refused call can find the previous refusal. Wait until the `refusals` count is higher than the one you read last, and give up after a short time.

## Refused reads at Basic

At Basic, a read of a file under `fs.deny_read` fails, but by default it leaves no refusal in the record or in `$TEGO_REASON`. Reporting every read to Tego's supervisor costs about 17 microseconds on every file open, so it is off.

To report refused reads, set `reason.reads: on` in the rules file:

```yaml
reason:
  reads: on
```

`tego rules check` prints a `reason-reads-off` note when it is off. A session that holds its reads or runs with `record: full` reports refused reads whatever `reason.reads` says. At Plus and Max, refused reads are recorded without this setting. [Rules file fields](/docs/rules-reference/) has the field.

## MCP tool refusals

MCP (Model Context Protocol) is how many agents call outside tools. When Tego's MCP relay refuses a tool call, the agent's MCP client gets a readable JSON-RPC error ([example](/docs/mcp-tools/#what-the-agent-sees)). Every MCP client can show that message to the model, so this is the one refusal reason that reaches every agent.

## Read refusals yourself

```sh
tego events <session> --last
```

prints the last refusal, gap or limit of a session. The dashboard's Refused tab lists every refusal of a session. [Sessions and records](/docs/sessions-and-records/) explains the record.

## Next steps

- [Claude Code](/docs/claude-code/): the hook that tells Claude why.
- [Approvals](/docs/approvals/): make an action wait for a person instead of refusing it.
- [Built-in refusals](/docs/built-in-refusals/): what every session refuses.
- [Exit codes](/docs/exit-codes/): what `tego run` returns.
