---
title: Secrets
description: "Keep SSH keys, cloud logins, .env files and API tokens away from an agent under Tego, with deny_read, env.pass, env.deny and the no-secrets preset."
summary: "Keep keys, tokens and .env files away from the agent."
section: Advanced usage
order: 3
---

A secret reaches an agent two ways: as a file it reads, or as a variable in its environment. Tego refuses reads of a built-in list of secret files in every session, and you add your own paths with `fs.deny_read`. For variables, `env.pass` lists the only ones the agent gets, and `env.deny` removes names even when they are passed.

## Files Tego refuses without a rule

Every rules file refuses reads of SSH keys, cloud and tool logins, agent token stores, password managers, browser profiles and the `.env` files in your project folder. [Built-in refusals](/docs/built-in-refusals/) lists each path.

Agent logins are on the list too: [Claude Code](/docs/claude-code/) and [Codex](/docs/codex/) show how to log in with a key instead. Leave the list on; [Switching the list off](/docs/built-in-refusals/#switching-the-list-off) says what you lose.

## Add your own secret files

```yaml
fs:
  deny_read:
    - ~/billing-exports
    - ~/.bash_history
    - ./config/prod.key
```

Each entry is a file or a folder and everything in it. Each entry must exist when the session starts, or `tego rules check` reports an error. Globs expand when the rules are checked. Your entries add to the built-in list.

Shell startup files are not on the built-in list. A token exported in `~/.bashrc` is readable by the agent, and an interactive shell the agent starts loads it. Add the file to `deny_read`, or keep tokens out of it.

## Keep secret variables out

With no `env.pass`, the agent gets every variable of the shell that starts the session, and `tego rules check` warns `secret-env` when some of them look like credentials.

The `no-secrets` preset passes only plain variables such as `PATH`, `HOME`, `LANG` and `TERM` ([Presets](/docs/presets/) has the list). Add each variable the agent needs:

```yaml
extends: [tego/no-secrets]
env:
  pass: [ANTHROPIC_API_KEY]
  deny: [AWS_SECRET_ACCESS_KEY]
```

| Field | What it does |
|---|---|
| `env.pass` | The only variables passed from your shell. `[]` passes none. Lists from presets and your file add up. |
| `env.deny` | Names removed even when `env.pass` lists them |
| `env.set` | Variables Tego sets for the agent, after `pass` and `deny` |

## A secret inside a folder the agent writes

A `deny_read` entry inside a folder in `fs.write`, such as `./keys/` under `./`, is harder to hold. The agent can rename or hard-link the file to a name outside the entry, then read it there.

| Level | Renamed or hard-linked secret |
|---|---|
| Basic | Refused. Tego holds each read open and checks the file itself, not its name. |
| Plus | Best effort |
| Max | Refused. The kernel refuses the rename or link out of the entry. |

`tego rules check` prints a `held-reads` warning when Tego will hold reads, and [`fs.reads`](/docs/rules-reference/#fs) sets when it does. A held read is slower than a direct one.

To have a person decide on each read of a file instead of refusing it, use `fs.ask_read`: see [Approvals](/docs/approvals/).

## Check what the agent gets

```
tego rules check agent.yaml
```

The rule table lists each `deny_read` entry and the levels it holds at. `--merged` prints the rules file with every preset laid in, including the final `env.pass`. [Testing rules](/docs/testing-rules/) covers the rest of the output.

## Next steps

- [Built-in refusals](/docs/built-in-refusals/): every path refused without a rule
- [Presets](/docs/presets/): what `no-secrets` sets
- [Refusals](/docs/refusals/): what the agent sees when a read is refused
- [Security and limits](/docs/security-and-limits/): what Tego does not stop
