---
title: MCP tools
description: "Set a rule for each MCP tool your agent calls: allow it, ask a person first, or refuse it. Tego's relay decides every call and records it."
summary: "Allow, ask about or refuse each MCP tool an agent calls."
section: Agents
order: 4
---

Add a `tools:` key to an MCP server in the rules file and Tego decides every call to that server's tools: it allows the tool, holds the call for a person, or refuses it. MCP (Model Context Protocol) is how many agents call outside tools. Tego's relay sits between the agent and the server, outside the agent, and writes each decision to the session's [record](/docs/sessions-and-records/).

## Set a rule for each tool

```yaml
ask:
  timeout: 2m                         # needed for an ask: list
mcp:
  - name: files
    command: [python3, /opt/mcp/files-server.py]
    tools:
      allow: [read_file, list_dir]    # present: every tool not listed is refused
      deny: [delete_file]
      ask: [write_file]               # held until a person answers
  - name: web
    url: https://mcp.example.com/mcp
    tools: {deny: [delete_file]}
```

On `files`, the agent may call `read_file` and `list_dir`, each `write_file` call waits for a person, and every other tool is refused. On `web`, only `delete_file` is refused.

Tego decides a call in this order:

1. A change made during the session ([below](#change-a-rule-during-a-session)).
2. `deny`: refused.
3. `ask`: held for a person.
4. An `allow` list that does not name the tool: refused.
5. Anything else: allowed.

- A tool name is exact, with no patterns, and sits in one list only.
- `tools: {}` puts the server behind the relay with nothing restricted, so you can still change rules during the session.
- A server with no `tools:` key runs without the relay.
- `command` starts a server the agent runs on this machine. `url` names a server it reaches over HTTP.

## What else the rules file needs

- **An `ask:` section** when any server has an `ask:` list. Without it, `tego rules check` stops with an error and the fix `add ask: {timeout: 2m}`.
- **An enforcing session.** `tego watch` and `tego run --observe` refuse a rules file with `tools:`, since nothing would keep the agent on the relay.
- **The `tego` binary in `exec.allow`**, when the rules file has that list. The agent's MCP client starts each server as `tego mcp relay`, so add the absolute path of `tego` (`command -v tego`).
- **A `net:` section** for a `url` server, so the agent can't reach the server around the relay ([what a missing `net:` allows](/docs/rules-files/#what-a-missing-section-means)). `net: {allow: []}` is enough.

`tego rules check` warns about the last two:

```sh
tego rules check agent.yaml
```

## Point the agent at the relay

For Claude Code, run the session as usual. When the command is `claude`, Tego adds `--mcp-config` with the relay's settings.

Any other MCP client reads the file named by `$TEGO_MCP_CONFIG` inside the session. It lists each server the way Claude Code's `mcpServers` setting does: a `tego mcp relay` command for a `command` server, and the relay's address for a `url` server.

```sh
tego run agent.yaml -- sh -c 'my-agent --mcp-config "$TEGO_MCP_CONFIG"'
```

The agent must start each server through the relay. Tego refuses a direct start of a declared server.

A session started with `sudo` (Plus or Max) gets no `$TEGO_MCP_CONFIG` file and no `--mcp-config` ([why](/docs/refusals/#who-is-told-why)). Set the agent's MCP client to start each `command` server as `tego mcp relay --server <name> -- <command...>`, with `<name>` the server's `name` in the rules file.

## What the agent sees

- Refused tools are left out of the server's tool list. Held tools stay listed.
- A refused call gets a JSON-RPC error the model can read:

```json
{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"Tego refused the MCP tool delete_file on files: the run's rules deny this tool","data":{"tego":{"rule":"mcp[files].tools.deny[delete_file]","reason":"mcp-tool-denied"}}}}
```

- A held call waits for an answer on the [dashboard](/docs/dashboard/) or from `tego approve` or `tego deny`. Other calls go on meanwhile. If a person refuses it, or nobody answers before the timeout, the agent gets the same kind of error. [Approvals](/docs/approvals/) covers answering.

This error reaches the model of any agent that calls tools through the relay. Other refusals reach agents in other ways: see [Refusals](/docs/refusals/).

## Change a rule during a session

```sh
tego mcp tools <session>                     # every tool, its rule now and why
tego mcp deny  <session> files read_file     # tightens: applies to the next call
tego mcp ask   <session> files write_file
tego mcp allow <session> files delete_file   # loosens: asks y/N first (--yes skips it)
tego mcp reset <session> files delete_file   # back to the rules file
```

The relay applies a change to the next call, within half a second. The change lasts until the session ends; to keep it, edit `tools:` in the rules file.

- A change that tightens a rule always applies.
- A change that loosens a rule past the rules file needs an Adjustable session, at Plus or Max. A Locked session, the default, refuses it. [Live changes](/docs/live-changes/) explains the two modes.
- A command run from inside any Tego session cannot loosen a rule.

On the dashboard, start it with `tego serve --preview` to see **MCP tools** in the menu. Pick a session and press Allow, Ask or Deny beside a tool. A loosening shows what it changes and asks you to confirm.

## What the record shows

Each tool call is a line with the server, the tool, the decision and the rule that made it, such as `mcp[files].tools.deny[delete_file]`. Each held call adds the question and its answer, and each change during the session adds who changed which tool. `tego events <session>` prints them, and the session's Timeline on the dashboard shows them.

## Limits

The relay holds an agent that uses its MCP client. An agent allowed to trace the relay's process can go around it: [Security and limits](/docs/security-and-limits/) lists what Tego does not stop.

To set business rules for your MCP tools, email us at hello@attention-span.ai.

## Next steps

- [Approvals](/docs/approvals/): answer held tool calls.
- [Live changes](/docs/live-changes/): Locked and Adjustable sessions.
- [Claude Code](/docs/claude-code/): run Claude Code with MCP servers under Tego.
