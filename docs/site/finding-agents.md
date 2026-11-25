---
title: Finding agents
description: "Find the AI agents running or installed on a machine with tego scan and tego agents, record one with tego watch, and govern a running one with tego adopt."
summary: "Find the agents on a machine, record them, and govern one already running."
section: Advanced usage
order: 8
---

`tego scan` looks for your agents: the ones running now, the ones installed, and their settings. `tego agents` lists every agent process on the machine, for any user (it needs root). Once you know the command an agent starts with, record a session of it with `tego watch`, or bring an agent that is already running under Tego with `tego adopt`.

## Look for your agents

Run it from your project folder:

```
cd ~/my-project
tego scan
```

`tego scan` takes one snapshot of your own processes, installed agent programs, their settings folders, configured MCP servers (the tool servers agents call through the Model Context Protocol), your systemd user services and the current folder's project files (`package.json`, `requirements.txt`). It recognises Claude, Codex, OpenCode and Gemini by default. It starts and changes no process, opens no process's environment, and makes no network request.

It saves the snapshot to `~/.tego/scan/last.json`, which `tego start` and the dashboard read to tick "Find your agents". Any program running as you can replace that file, so treat it as a note, not proof.

A match is a name, not proof of what a program is. A process can pick its own name, and a settings folder can be left from an old install.

| Flag | What it does |
|---|---|
| `-v`, `--verbose` | Adds the rule and the source behind each match |
| `--json` | Prints the snapshot as JSON |
| `--all-mine` | Also lists interpreters (`python`, `node`) that match no rule |
| `--signature <name>=<pattern>` | Adds your own rule, such as `my-agent=python3 .../my-agent.py`. Repeat it, up to 64. |
| `--no-default-signatures` | Starts from no rules, so only your `--signature` rules match |
| `--advanced` | As root: every user's processes, system services, cron and container hints |

`--advanced` needs root of the machine itself: `sudo "$(command -v tego)" scan --advanced`.

`tego scan` refuses to run on WSL (Windows) in this release.

### When /etc is a link

If `/etc` or `/etc/passwd` is a symbolic link, the scan as a whole refuses before discovery: it looks for no agents. To learn who ran it, the scan reads `/etc/passwd` and refuses any link on that path, even one owned by root. The account-evidence collector accepts verified links (the collector is the part of the scan that reads account files for its report), but the scan stops before it gets there. This affects store-path and image-based distribution layouts that use such links, for example `/etc -> /usr/etc` or `/etc/passwd -> /usr/lib/passwd`. The actual paths decide, not the distribution's name.

The scan prints `Read: none; scan not performed.` and fails with exit 125. Its JSON names a `meta` source with reason `owner` and the exclusion `scan-not-performed`. No new snapshot is saved.

Ask the distribution administrator whether a layout with a regular `/etc` folder and a regular `/etc/passwd` file is available. Do not replace distribution-managed links just to run the scan. Where the linked layout is required, record a session with `tego watch` instead.

### Use it as a CI check

```
tego scan --check
```

`--check` prints the same report, saves nothing, and sets the exit code: 1 when an agent process runs outside Tego ([Exit codes](/docs/exit-codes/) lists the rest). Some processes of yours don't let their program file be read, such as ssh-agent or a running `tego run`, and a program can make itself unreadable on purpose. So a clean result never proves that no agent runs outside Tego.

## List agent processes for every user

```
sudo "$(command -v tego)" agents
sudo "$(command -v tego)" agents --follow
```

`tego agents` lists each agent process with its process id, parent, program and arguments, and whether it runs inside a Tego session or outside every one. `--follow` keeps running and prints a line when an agent starts or exits, until you press Ctrl-C. `--children` adds each process an agent starts, and `--json` prints one JSON object per line. `--signature` and `--no-default-signatures` work as for `tego scan`.

It only observes: it signals, moves and changes no process. Listing an agent does not protect anything.

## Record an agent with tego watch

```
tego watch -- claude
```

`tego watch` runs the command as a session that records every program it starts, file it opens, creates, removes or renames, and connection it makes. No rule refuses anything. The command's exit code is passed through as `tego watch`'s own.

| Flag | What it does |
|---|---|
| `--record full\|summary\|off` | How much is recorded. Default: `full`, or the rules file's `record:` with `--boundary` |
| `--boundary <file \| name>` | Holds the command to a rules file, the same as `tego run <file> -- <command>` |
| `--tier <level>` | With `--boundary`: pin the [protection level](/docs/tiers/) |
| `--no-summary` | At the end, print only where the record is |

Turn the recording into a first rules file with `tego rules learn`: see [Learning rules](/docs/learning-rules/).

## Govern an agent that is already running

`tego adopt` needs root, so run it through `sudo`:
```
sudo "$(command -v tego)" adopt --pid 4242
sudo "$(command -v tego)" adopt --pid 4242 --boundary agent.yaml
```

`tego adopt` moves the agent's own process tree, and nothing else, into a new Tego session at Plus. From that moment on it records from the kernel every program the agent starts, file it opens and connection it makes. What the agent did before, and what it does through files and connections it already had open, is not recorded. It needs root.

`--boundary` also holds the agent to the rules file's file rules and `exec.allow` list. Some rules cannot be added to a process that is already running. Tego refuses them by name before anything moves: `net`, `ask`, `env`, `models`, `mcp`, memory and time limits, budgets and command rules with arguments. To hold an agent to its whole rules file, start it with `tego run`.

Run through `sudo`, `tego adopt` still adopts only your own processes. Name another user's with `--uid <uid>`. It refuses Tego itself, the shell you typed the command in, system managers and processes in containers.

To release an agent you adopted with root, press Ctrl-C, or run `tego session stop <session>` or `tego adopt --release --pid <pid>`. Its processes go back where they came from and keep running, unrecorded.

## Find the rules files on this machine

`tego rules list` shows every rules file Tego knows for you, and whether today's file is the one your last session ran: see [Testing rules](/docs/testing-rules/#list-the-rules-files-tego-knows).

## Next steps

- [Learning rules](/docs/learning-rules/): turn a `tego watch` session into a rules file
- [Other programs](/docs/other-programs/): run any program under a rules file
- [Sessions and records](/docs/sessions-and-records/): read what a session recorded
