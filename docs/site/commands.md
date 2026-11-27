---
title: Commands
description: "Every tego command and verb with its usage and main flags: start, run, session, rules, machine, approvals, live changes, the record and older names."
summary: "Every command and verb, with usage and main flags."
section: Reference
group: Command line
order: 1
---

This page lists every `tego` command with its usage line and the flags you reach for. Most commands follow git's shape: a noun, then a verb, such as `tego session list`.

```
tego help
tego help -a
tego help <command>
tego <command> -h
```

`tego help` lists the common commands, `tego help -a` lists all of them, and `tego <command> -h` prints every flag of one command.

A command that takes `<session>` accepts the session name (such as `claude-code-a1b2`) or its run id. [Sessions and records](/docs/sessions-and-records/) explains both. Exit codes are on [Exit codes](/docs/exit-codes/).

## Get started

| Command | What it does |
|---|---|
| `tego start` | Sets up an agent in four steps: Agent, Login, Project, Rules. With no agent installed and signed in, it offers a demonstration agent that needs no account and runs it once. It starts the dashboard and prints the command that starts a session. Runs only in a terminal; takes no arguments. |
| `tego dashboard` | Starts the dashboard or offers the one already running. On Linux it prints the link; on macOS and Windows it opens your browser. See [Dashboard](/docs/dashboard/). |
| `tego dashboard --stop` | Windows only: stops the relay, and the dashboard when no session is running, so Tego's Linux can stop. See [Windows](/docs/supported-systems/#windows). |
| `tego shell` | macOS and Windows only: opens a shell inside Tego's Linux. On a Mac it starts in your last project. Takes no arguments. |

## Run an agent

```
tego run <agent.yaml | name> [--tier <t>] [--record full|summary|off] [--status-file <absolute-path>]
         [--no-summary] [--service] [--observe] [--offline] [-v] [-- <cmd> [args]]
```

| Flag | Meaning |
|---|---|
| `--tier auto\|landlock\|cgroup\|bpflsm` | Pin the [protection level](/docs/tiers/) for this session. `cgroup` and `bpflsm` need root. |
| `--record full\|summary\|off` | Override the rules file's `record:` value. |
| `--observe` | Record only. Nothing is enforced. |
| `--offline` | A host name that does not resolve is a warning, not an error. |
| `--service` | Exit 143 after `tego session stop`, so a service manager does not restart the agent. See [Services](/docs/services/). |
| `--status-file <path>` | Write the session's end status to this file. |
| `--no-summary` | Print no summary when the agent exits. |
| `-v` | Print every note from checking the rules file at start. |
| `-- <cmd> [args]` | Run this command in place of the rules file's `command:`. |

## Sessions

| Command | What it does |
|---|---|
| `tego session list [--json]` | Lists sessions. |
| `tego session show <session> \| --last [--json] [--verify]` | Shows what a session did and each refused action with its rule. `--verify` also checks the record's hash chain. |
| `tego session stop <session> [--grace <d>]` | Stops a running session. `--agent <name>` in place of `<session>` stops every running session of that agent. `--grace` sets how long to wait before the session is killed. |
| `tego session pause <session>` | Pauses a running session. |
| `tego session resume <session>` | Resumes a paused session. |

`tego session show` also checks CI receipts with `--check`, `--require-ended`, `--verify-ci` and `--bundle`. [CI](/docs/ci/) shows how.

## Rules files

| Command | What it does |
|---|---|
| `tego rules create [<dir>]` | Writes `agent.yaml` in the folder (default: the current one). Flags below. |
| `tego rules edit <agent \| file>` | Opens a copy of the rules file in `$VISUAL` or `$EDITOR` (`vi` when neither is set) and saves it only when it passes `tego rules check`. |
| `tego rules check <agent \| file \| -> [--json]` | Checks a rules file and shows what it enforces. Runs nothing. `-` reads the file from standard input. |
| `tego rules learn <session>` | Writes a rules file from what a session did. Flags below. |
| `tego rules history <agent \| file> [--json]` | Shows the changes made to a rules file. |
| `tego rules undo <agent \| file> [<id>] [--yes]` | Undoes the newest change to a rules file, or the change `<id>`. |
| `tego rules list [<name \| path>] [--json] [-v]` | Finds the rules files on this machine and checks each one without running an agent. With a name or path, shows that one file. `-v` adds full hashes, warnings and the compiled rules. |
| `tego rules <session> \| --last [--json]` | Shows the rules a session runs under. |

`tego rules create` flags:

| Flag | Meaning |
|---|---|
| `--preset <list>` | Build the file from [presets](/docs/presets/), a comma list of `no-secrets`, `no-prod`, `repo-only-writes`, `ci`. |
| `--agent claude-code\|codex` | Write a rules file for Claude Code or Codex. |
| `--write <dir>` | With `--preset` or `--agent`: a folder the agent may write. Repeat for more. |
| `--allow-host <host[:port] \| @group>` | With `--preset` or `--agent`: a host the agent may reach, or a host group such as `@npm`. Repeat for more. |
| `--command <line>` | With `--preset`: the agent's command line. |
| `--prompt <text>` | With `--agent`: a first task for the agent. |
| `--live-mode locked\|adjustable` | How the rules may change during a session. See [Live changes](/docs/live-changes/). |
| `--name <agent>` | The agent's name. Default: the folder name. |
| `--force` | Replace an `agent.yaml` that `tego rules create` did not write. |
| `--list` | Print the presets, agents and host groups. |

`tego rules learn` flags:

| Flag | Meaning |
|---|---|
| `--save <name>` | Save the result as `~/.config/tego/agents/<name>.yaml`, so `tego run <name>` finds it. Never replaces a file. |
| `--out <file>` | Write the result to a new file. Never replaces a file. |
| `--allow-host <host[:port]>` | Allow a host the session reached by name. Repeat for more. |
| `--reads on\|off` | `on` sets `reason.reads: on` in the result. |
| `--workspace <dir>` | The folder writes may be allowed under. Default: the session's working folder. |

`tego rules check` flags:

| Flag | Meaning |
|---|---|
| `--test <table.yaml> [--tier <t>[,<t>]]` | Check a table of actions and the answer you expect for each. See [Testing rules](/docs/testing-rules/). |
| `--exec <line>` | Show how the `exec:` rules answer one command line at each level. |
| `--merged` | Print the rules file with every preset and profile it extends laid in. |
| `--effective` | Print the merged file with the machine's baseline applied. |
| `--offline` | A host name that does not resolve is a warning. |
| `--upgrade` | Rewrite the file to the newest format version. |

## Check this machine

| Command | What it does |
|---|---|
| `tego machine check [--json] [--no-scope] [--require landlock\|cgroup\|bpflsm]` | Shows which protection level this machine can enforce. `--require` exits 211 when the machine is below that level. `--no-scope` checks the current shell without trying a user scope. |
| `tego machine test [--json] [--tier auto\|landlock\|cgroup\|bpflsm]` | Runs four harmless actions that the rules must refuse, and reports each result. `cgroup` and `bpflsm` need root. |

[Self-check](/docs/self-check/) explains both reports.

## Answer what a session asks

| Command | What it does |
|---|---|
| `tego ask [<session>] [<ask_id>] [--json]` | Lists the actions waiting for an answer. With no argument, lists them for every running session. |
| `tego approve [<session>] <ask_id> [--always] [--json]` | Allows a waiting action. `--always` also allows the same action, rule and target for the rest of the session. |
| `tego deny [<session>] <ask_id> [--always] [--json]` | Refuses a waiting action. `--always` works as for `approve`. |
| `tego alternate [<session>] <ask_id> --file <path> [--always] [--json]` | Answers a waiting file open with another file. |

[Approvals](/docs/approvals/) explains which actions wait.

## Change a running session's rules

| Command | What it does |
|---|---|
| `tego block <session> exec\|net\|path\|read\|write <value> [--for D \| --until T]` | Refuses a program, host or path in a running session. `tego block --list <session>` lists the blocks. |
| `tego unblock <session> <kind> <value>` | Removes a block. |
| `tego grant <session> read\|net\|exec <value> [--for D \| --until T] [--note TEXT] [--yes]` | Gives an Adjustable session more access, inside its fence. |
| `tego lift <session> read\|net\|exec <value> [--for D \| --until T] [--note TEXT] [--yes]` | Allows one of an Adjustable session's refusals, inside its fence. |
| `tego restore <session> read\|net\|exec <value>` | Refuses a granted or lifted entry again. |
| `tego rule <session> <seq> --block\|--ask\|--allow [--folder\|--level N\|--command\|--host] [--dry-run]` | Turns one line of a session's record into a rule in its rules file. |

[Session control](/docs/session-control/) and [Live changes](/docs/live-changes/) explain these commands.

## Read the record

| Command | What it does |
|---|---|
| `tego events <session> [--json] [--kind K] [--source S] [--verdict V] [--rule R] [--step N] [--limit N] [--last \| --follow]` | Lists a session's events. |
| `tego events <session> --verify [--json]` | Checks the record's hash chain. |
| `tego drift <session> [--json] [--aggregate]` | Compares what the rules declared with what the session did. |
| `tego measure <session> [--json]` | Shows a session's steps, tokens, cost and time. |
| `tego status [<session> \| --agent <name>] [--json] [--all]` | Shows the state of a session. |
| `tego gc [--keep <d>] [--dry-run] [--builds] [--json]` | Removes orphaned and expired sessions. |

## Supervise other programs

| Command | What it does |
|---|---|
| `tego watch [--boundary <agent.yaml \| name>] [--tier <t>] [--record <mode>] [--offline] [--no-summary] [-v] -- <command> [args]` | Runs a command and records the programs it starts, the files it opens, creates, removes and renames, and its connections. Without `--boundary` nothing is refused. |
| `tego adopt --pid <pid> [--uid <uid>]... [--boundary <agent.yaml \| name>] [--record <mode>]` | Needs root. Supervises an agent that is already running. `tego adopt --release --pid <pid>` lets it go. |
| `tego agents [--signature <rule>]... [--follow]` | Needs root. Lists the agent processes running here. Observes only. |
| `tego scan [--advanced] [--json] [-v] [--check [--allow-unreadable-programs]] [--all-mine] [--signature <rule>]... [--no-default-signatures]` | Looks for your running agents, installed candidates and their settings. |

[Finding agents](/docs/finding-agents/) shows how to use them.

## Tools for agents

| Command | What it does |
|---|---|
| `tego mcp tools <session> [--json]` | Lists a running session's MCP tools and their rules. |
| `tego mcp allow\|ask\|deny\|reset <session> <server> <tool> [--yes]` | Changes the rule for one MCP tool in a running session. See [MCP tools](/docs/mcp-tools/). |
| `tego route list <session> [--json]` | Lists a running session's model routes. |
| `tego route set <session> <endpoint> <route> [--yes]` | Sends an endpoint's model requests to another route. `tego route clear <session> <endpoint>` undoes it. See [Model routes](/docs/model-routes/). |
| `tego dns <name> [--type A] [--json]` | Queries a session's DNS broker. |

## About Tego

| Command | What it does |
|---|---|
| `tego setup [--json] [-v] [--no-scope]` | Shows where this machine is in setup and what to type next. |
| `tego serve [--addr 127.0.0.1:8484] [--ledger DIR] [--open] [--preview]` | Starts the dashboard server. `--preview` adds the preview pages to the menu. |
| `tego version [--json]` | Prints the build's versions. |
| `tego licenses` | Prints the licence texts and third-party notices. |
| `tego uninstall [--yes] [--stop-agents] [--delete-records]` | Removes Tego. See [Install](/docs/install/#uninstall). |

## Older names

These names still work, with the same flags and exit codes. Use the new names in scripts and docs.

| Older name | New name |
|---|---|
| `tego init` | `tego rules create` |
| `tego compile` | `tego rules check` |
| `tego learn` | `tego rules learn` |
| `tego contracts` | `tego rules list` |
| `tego receipt` | `tego session show` |
| `tego doctor` | `tego machine check` |
| `tego test` | `tego machine test` |
| `tego stop` | `tego session stop` |
| `tego pause` | `tego session pause` |
| `tego resume` | `tego session resume` |

## Next steps

- [Exit codes](/docs/exit-codes/): what each command returns.
- [Rules file fields](/docs/rules-reference/): every field of a rules file.
- [Quickstart](/docs/getting-started/): run a first session end to end.
