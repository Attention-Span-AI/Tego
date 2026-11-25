---
title: Rules files
description: "What a Tego rules file is, where it lives, what each section controls, what a missing section allows, and how presets and extends combine."
summary: "What a rules file holds, where it lives, and what a missing section means."
section: Core concepts
order: 1
---

A rules file is a YAML file that says what one agent may do. It names the files the agent may write and never read, the programs it may run and the hosts it may reach. It also names the actions that wait for a person and the limits that end the session. Each entry in it is a rule. Tego reads the file when a session starts and enforces it until the session ends. Older docs and some commands call it a contract.

```yaml
version: 0
name: my-agent
command: ["claude"]
extends: [tego/no-secrets, tego/repo-only-writes]
fs:
  write: ["./src/", "./tests/"]
exec:
  allow: ["bash", "git", "python3"]
net:
  allow: ["api.anthropic.com:443"]
```

Every rules file starts with `version: 0`, the agent's `name` (lowercase letters, digits and dashes, up to 40 characters), and the `command` that starts the agent.

## Where a rules file lives

A rules file lives in one of two places, and `tego run` finds it by the agent's name.

| Place | Path | Written by |
|---|---|---|
| Your user | `~/.config/tego/agents/<name>.yaml` | `tego start`, `tego rules learn --save` |
| A project | `agent.yaml` in the project folder, or `.tego/agents/<name>.yaml` in it | `tego rules create` |

`tego run <name>` looks in the current folder's project first, then in your user's folder. When both hold the same name, `tego run` refuses and asks you to give the file's path. `tego run <path>` runs a file by its path.

To find the rules files on this machine, use [`tego rules list`](/docs/testing-rules/#list-the-rules-files-tego-knows).

## The sections

Each section controls one kind of action. [Rules file fields](/docs/rules-reference/) lists every field, its values and its default.

| Section | What it controls |
|---|---|
| `fs` | Files: the folders the agent may write (`fs.write`), the files it may never read (`fs.deny_read`), and file actions that wait for a person (`fs.ask`) |
| `net` | Network: the hosts and ports the agent may reach (`net.allow`), and connections that wait for a person (`net.ask`) |
| `exec` | Programs: what the agent may run (`exec.allow`) and what it may never run (`exec.deny`) |
| `env` | Environment variables: which ones the agent gets (`env.pass`), which it never gets (`env.deny`), and values Tego sets (`env.set`) |
| `limits` | Limits that end the session: time, idle time, repeats, tokens, cost, memory and processes |
| `ask` | How actions that wait for a person behave: the timeout and what happens when nobody answers |
| `models` | The AI model hosts the agent calls, so Tego can count tokens and cost |
| `mcp` | MCP servers (Model Context Protocol, the way agents call tools) and rules for each of their tools |
| `live` | Whether the rules stay fixed for the session (the default) or can change within limits |
| `extends` | The presets the file builds on |
| `tier` | The protection level the session needs |
| `record` | How much detail the session's record keeps |

## What a missing section means

Each section you leave out has its own default:

| Left out | What the agent may do |
|---|---|
| `fs` | Read any file except Tego's [built-in refusals](/docs/built-in-refusals/). Write nothing. |
| `net` | Reach every IP host and port. Connect only to the Unix sockets its own session made, unless `host_sockets: true`. |
| `exec` | Run any program. |
| `env.pass` | Get your whole environment, as it was where you typed `tego run`. |
| `limits` | Run up to the machine's ceilings, which are unlimited unless an admin set them ([Machine settings](/docs/machine-settings/)). |

A section that is present but empty is strict:

- `net: {}` or `net.allow: []` refuses every connection.
- `exec: {}` or `exec.allow: []` lets the agent run only its own `command`.
- `fs: {}` refuses every write, as a missing `fs` does.

A section with nothing under it, such as `net:` followed only by commented-out lines, is an error. Write `net: {}` or remove the line.

## Presets and extends

A preset is a ready-made rules file that ships with Tego. Its name starts with `tego/`. Your rules file builds on presets with `extends`:

```yaml
extends: [tego/no-secrets, tego/no-prod, tego/repo-only-writes]
```

Tego has four presets, listed with exactly what each sets on [Presets](/docs/presets/).

`extends` takes one name or a list of up to 8. Tego merges the presets from left to right, then lays your file on top. The sections combine by kind:

- **Lists add up.** `fs.write`, `net.allow`, `exec.allow` and the other lists hold the presets' entries first, then yours. A preset can't take away an entry you wrote, and you can't take away a preset's.
- **Refusals only grow.** No file removes an entry from another file's `fs.deny_read` or `fs.deny_write`, or from the built-in refusals. [Rules file fields](/docs/rules-reference/) lists the levels where `fs.deny_write` holds.
- **Single values: your file wins.** For a value such as `limits.wall` or `record`, your file's value is used. When two presets in one `extends` list set the same value differently, the file is an error (`extends-conflict`) unless your file sets it.
- **Assurance only gets stricter.** When any file sets `fs.assurance` or `exec.assurance` to `kernel`, the session uses `kernel`.
- **Two settings are yours alone.** A preset can't set `fs.reads: direct` or `host_sockets: true`; only your own file can.

A preset's section counts as present, so a file that extends `tego/no-prod` reaches only the hosts it lists itself, even with no `net:` section of its own.

To see the merged result, run `tego rules check --merged <file>` ([Testing rules](/docs/testing-rules/)).

## Next steps

- [Rules file fields](/docs/rules-reference/): every field, value and default.
- [Presets](/docs/presets/): what each preset sets.
- [Testing rules](/docs/testing-rules/): check a rules file before a session.
- [Learning rules](/docs/learning-rules/): write a rules file from what a session did.
