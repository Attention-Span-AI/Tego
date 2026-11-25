---
title: Testing rules
description: "Check a Tego rules file before an agent runs under it: read the rule table, test made-up actions, edit it safely and undo a change you regret."
summary: "Check, test, edit and undo a rules file before a session runs it."
section: Advanced usage
order: 1
---

Run `tego rules check` on a rules file before any session uses it. It shows what each rule allows, refuses or holds at each [protection level](/docs/tiers/), warns about rules that will not do what you expect, and runs nothing. `--test` goes further: it checks a list of made-up actions against the rules and tells you which ones get a different answer than you wrote down.

## Check a rules file

Give the agent's name or the file's path:

```
tego rules check agent.yaml
tego rules check my-project
```

Tego loads the file and every preset it extends, then prints the rule table: each rule, the levels it holds at, and one reading of each command entry. A host name that does not resolve is an error; `--offline` makes it a warning, and the session resolves the name when it starts. `-` in place of the file reads the rules from standard input.

The command exits 0 when the file passes and 1 when it has an error. See [Exit codes](/docs/exit-codes/).

| Flag | What it prints |
|---|---|
| `--json` | The rule table as one JSON object |
| `--merged` | Your rules file with every preset laid in: the one file the session enforces |
| `--exec '<command line>'` | How that one command line is decided at each level |
| `--test <table.yaml>` | The result of each row of a test table (below) |
| `--tier <list>` | With `--test`: only these levels, such as `landlock,cgroup` |

`--merged`, `--exec`, `--test` and `--json` are separate outputs. Give one at a time (`--test` and `--json` combine).

### Warnings worth reading

A warning names the file, line and column, says what goes wrong, and gives a fix:

```
warning: warnings-only.yaml:11:14: deny_read: [] disables the built-in list (~/.ssh, ~/.aws, ~/.netrc, ~/.gnupg, npm/git/gh/docker/kube/gcloud credentials, browser profiles, .env files) [deny-read-disabled]
  fix: remove deny_read: to keep the built-in list
```

| Code | What it means |
|---|---|
| `budget-unmetered` | A `tokens`, `cost_usd` or `repeats` limit has nothing to count it with, so every session of this file is refused. See [Budgets](/docs/budgets/). |
| `secret-env` | The file has no `env.pass`, so the agent gets your whole environment, and some variables look like credentials. See [Secrets](/docs/secrets/). |
| `deny-read-disabled` | `fs.deny_read: []` switched off the [built-in list](/docs/built-in-refusals/#switching-the-list-off) of secret files. |
| `exec-rule-coverage` | `exec:` has `deny` rules and no `allow` list, so every other program runs, a copy of a denied program under another name included. Add `exec.allow` to close it. |

The rule table also prints `reason-reads-off` for a file that can run at Basic: refused reads at Basic leave no record line ([Refusals](/docs/refusals/#refused-reads-at-basic)).

## Test made-up actions

A test table is a YAML file of actions and the answer you expect for each. Write one for the things that must never change, and run it after every edit:

```yaml
version: 0
tests:
  - name: the agent writes its report
    action: fs.write
    path: ./out/report.md
    expect: allow
  - name: no connections to the internal tools
    action: net.connect
    host_port: mcp.internal:8080
    expect: refused
    rule: unmatched
  - name: ripgrep runs
    action: exec
    argv: [rg, -n, needle]
    expect: allow
```

```
tego rules check agent.yaml --test checks.yaml
```

Each row needs `action` and `expect`. `expect` is `allow`, `ask` or `refused`. `rule` is optional: it names the rule that must decide the row (`unmatched` when no rule matches). `tier` limits a row to one level.

| Action | Keys |
|---|---|
| `fs.read`, `fs.write`, `fs.delete`, `fs.mkdir`, `fs.attr` | `path` |
| `fs.rename`, `fs.link` | `path`, `dest` |
| `exec` | `argv` (or `path`) |
| `net.connect`, `net.bind`, `net.send` | `host_port`, or `path: unix:<socket>` |
| `net.http` | `host_port`, `method`, `path` |

Each row is answered at every level a session of the file can get. The output marks each row `PASS` or `FAIL`; a failing row says, per level, what it got and which rule decided. The answers come from the rules file itself, so `--test` answers rows at Plus (`cgroup`) and Max (`bpflsm`) without root, though a session at those levels needs root:
```
PASS a hard link inside the write entry
FAIL an anonymous image is allowed (verdicts.yaml:77): at landlock got refused via exec-anon; at cgroup got refused via exec-anon; at bpflsm got refused via exec-anon, want allow
19 rows: 16 passed, 3 failed
```

A failing row makes the command exit 1, so a test table works as a CI step.

## Command rules: what to watch for

`exec.allow`, `exec.deny` and `exec.ask` take a program (`git`) or a program with words (`git push`). Check one command line before you rely on a rule:

```
tego rules check agent.yaml --exec 'git -C . push'
```

- **`exec.deny` wins.** A deny rule beats every allow rule. There is no exception syntax.
- **`exec.ask` never asks.** [Approvals](/docs/approvals/#what-can-wait-for-a-person) explains.
- **Deny the short form.** `rm -rf` does not cover `rm -r`, and `rm -r` removes the same tree. Write `deny: [rm -r]`.
- **Options an allow rule leaves out are free.** `allow: [git push origin main]` still allows `--force`. Deny the option.
- **Rules see programs started, not effects.** `deny: [git push]` does not stop a git library in the agent's own code, `git send-pack`, or `curl` to the server. Limit those with `net` and `fs` rules.
- **Put no `--` ahead of the subcommand.** An allow entry does not admit its command when the command line puts `--` before the subcommand; write the command without it.
- **One program file can have many names.** A multicall program, such as uutils coreutils on Ubuntu 25.10 and 26.04 (about 115 names for one file) or busybox, picks what it does from the name it was started by. `exec.deny` and `exec.ask` match every name it can pick from, so denying a utility name can refuse a command an allow entry admits. `exec.allow` does not read those names.
- **Code passed inline is not read.** `python -c '...'`, `sh -c '...'` and `node -e '...'` are not commands to the rules.
- **Aliases from config files are not read.** cargo, gh and aws aliases, and settings such as `NPM_CONFIG_*` and `GIT_CONFIG_PARAMETERS`, change what a command does without changing its words.
- **The check is a preview.** `tego rules check` never allows what the session refuses, but the session can refuse what the check allows (a missing interpreter, a file it cannot read).

## Edit a rules file safely

```
tego rules edit my-project
```

Tego opens a copy in `$VISUAL` or `$EDITOR` (`vi` when neither is set), checks the copy when you close the editor, and saves it only when it passes:

```
✓ Saved and checked agent.yaml
```

A copy with errors is not saved. Your edit is kept beside the file as `agent.yaml.rejected`, and the command exits 1.

## See and undo changes

The dashboard's Change rules page, `tego rules edit` and `tego rule` record each change they make to a rules file. Once a session on this machine has run the file, list its changes:

```
tego rules history my-project
```

It prints the newest 20 changes; `--json` prints all of them. Undo the newest change, or name one by its id:

```
tego rules undo my-project
tego rules undo my-project <id>
```

An undo that gives the agent more access asks you to type `undo` first. Without a terminal, pass `--yes`. When the file changed after the change you name (a later change, or an edit by hand), the undo is refused so the later text is not lost.

## List the rules files Tego knows

```
tego rules list
tego rules list my-project
```

`tego rules list` shows the rules files Tego finds for you: the agents in `~/.config/tego/agents/`, the current folder's `agent.yaml` and `.tego/agents/`, and the files your recorded sessions ran. Each row gives the check result for today's file, when a session last started it, at which level, and whether today's file is the same text that session ran. Give a name or a path to see one file's rules with the file and line each rule comes from. It changes no file and starts nothing. `--json` prints the same as JSON.

## Next steps

- [Rules file fields](/docs/rules-reference/): every field and its default
- [Learning rules](/docs/learning-rules/): get a first rules file from a real session
- [Secrets](/docs/secrets/): keep keys and `.env` files away from the agent
- [Commands](/docs/commands/): every flag of `tego rules`
