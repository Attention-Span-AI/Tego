---
title: Claude Code
description: "Run Claude Code under Tego: write its rules file, log in with an API key or a setup token, and read the note Tego adds when it refuses an action."
summary: "Run Claude Code under a rules file, logged in with a key or a token."
section: Agents
order: 1
---

To run Claude Code under Tego, write a rules file for it with `tego start` or `tego rules create --agent claude-code`, give it a login through an environment variable, and start it with `tego run`. Tego refuses what the rules file does not allow and tells Claude why.

## Pick a setup

| You want | Use |
|---|---|
| The full-screen interface, typing tasks yourself | `tego start`, and pick **Claude Code** ([Quickstart](/docs/getting-started/)) |
| One task in print mode (`claude -p`), for scripts | `tego rules create --agent claude-code` |
| A file to start from and edit | [`examples/agents/claude-code-interactive.yaml`](https://github.com/Attention-Span-AI/Tego/blob/main/examples/agents/claude-code-interactive.yaml) or [`examples/agents/claude-code.yaml`](https://github.com/Attention-Span-AI/Tego/blob/main/examples/agents/claude-code.yaml) |

## Log in

Claude Code cannot read its usual login under Tego. Its token stores in your home (`~/.claude/.credentials.json`, `~/.claude.json`) are on the [built-in refusals](/docs/built-in-refusals/) list, with no exception for the agent the session runs. Give it a login through the environment instead:

- **Claude subscription (Pro, Max, Team or Enterprise):** run `claude setup-token` once, outside Tego. Export the token it prints as `CLAUDE_CODE_OAUTH_TOKEN`.
- **API key:** export it as `ANTHROPIC_API_KEY`.

```sh
claude setup-token
export CLAUDE_CODE_OAUTH_TOKEN=<the token it printed>
```

`tego start` runs `claude setup-token` for you when you pick **Claude subscription**.

Claude Code also keeps its settings and sessions in `~/.claude`. The rules files Tego writes set `CLAUDE_CONFIG_DIR` to a folder in the project (`.tego/claude/`), so Claude Code starts there with an empty state and your `~/.claude` is never written.

## Write the rules file

From the project's folder:

```sh
tego rules create --agent claude-code --write src/ --prompt "Fix the failing test in src/"
```

This writes `agent.yaml` in the project. It starts from the `no-secrets`, `no-prod` and `repo-only-writes` [presets](/docs/presets/) and adds what Claude Code needs:

```yaml
command: ["claude", "-p", "--permission-mode", "acceptEdits", "--", "Fix the failing test in src/"]
fs:
  write:
    - "./src/"            # --write
    - "./.tego/tmp/"      # TMPDIR: the agent's temporary files stay in the project
    - "./.tego/claude/"   # Claude Code's own folder: its login, settings and sessions
    - "/dev/null"         # its Bash tool redirects into it
    - "/dev/tty"          # the full-screen interface draws there
env:
  pass:
    - "CLAUDE_CODE_OAUTH_TOKEN"   # Claude Code's login (claude setup-token)
    - "ANTHROPIC_API_KEY"         # or an API key
  set:
    CLAUDE_CONFIG_DIR: "${TEGO_PROJECT_DIR}/.tego/claude"
    XDG_RUNTIME_DIR: "%R"
    DISABLE_AUTOUPDATER: "1"
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1"
harness: claude-code
capture: forwarder
models:
  - {provider: anthropic, host: api.anthropic.com, port: 443}
```

- Without `--write`, only `./out/` and Claude Code's own folders are writable.
- `capture: forwarder` sends Claude Code's model calls through a listener Tego runs on this machine, so each call is in the session's [record](/docs/sessions-and-records/).
- `tego rules create --list` prints the setup notes for each agent.

Then run it:

```sh
tego run agent.yaml
```

[Rules file fields](/docs/rules-reference/) explains every field.

## The full-screen interface

`examples/agents/claude-code-interactive.yaml` is the starting point for the full-screen `claude`. It differs from the print-mode file in three places:

- `command: ["claude"]`, with no prompt: you type tasks in Claude Code's window.
- `capture: off` and `net.allow: ["tcp://api.anthropic.com:443"]`. Claude Code's first connectivity check goes straight to `api.anthropic.com` and ignores the forwarder, so the interface reaches the model directly. The connection is recorded; the content of the model calls is not.
- `limits.stall_after: 1h` in place of a wall-clock limit. Typing at the terminal counts as activity, so a working session is not cut off.

This file lets Claude Code write the whole project (`./`), so keep the rules file outside the project: Tego refuses a rules file the agent could rewrite ([Built-in refusals](/docs/built-in-refusals/#tegos-own-files)).

## What Claude sees when Tego refuses an action

The refused action fails with an ordinary error. On a session you start without `sudo`, Tego also gives Claude a note beside the tool result, through a Claude Code hook:

```text
Tego, this run's access control, refused 1 action:
Scope: whole run, including startup and background work; tool call and session attribution unavailable.
- Tego refused write "/home/user/out.txt": this run may not write to that path (rule fs.write).
```

Claude reads the reason and can carry on another way. Tego installs the hook for this session only: when the command is `claude`, it writes a settings file in the session's private folder and adds `--settings <that file>` to the command. Your `~/.claude`, `CLAUDE_CONFIG_DIR` and the project's `.claude/` are not written. If you pass your own `--settings`, Tego merges its hook into it.

[Refusals](/docs/refusals/#who-is-told-why) says which sessions get the hook.

### When the hook cannot load

Claude Code loads no hooks in safe mode or bare mode, so Tego refuses those sessions before they start, with exit code 125:

- `--safe-mode` or `CLAUDE_CODE_SAFE_MODE=1`
- `--bare` or `CLAUDE_CODE_SIMPLE=1`

To run one anyway, set `harness: none` in the rules file. Claude then gets no note.

If `command` starts a wrapper script in place of `claude`, Tego leaves the command as it is and sets `TEGO_CLAUDE_SETTINGS`. Have the script pass `--settings "$TEGO_CLAUDE_SETTINGS"` to `claude`.

## Next steps

- [Refusals](/docs/refusals/): what the agent sees for each kind of refused action.
- [Approvals](/docs/approvals/): hold a write for a person to answer.
- [MCP tools](/docs/mcp-tools/): rules for each tool Claude Code calls.
- [Budgets](/docs/budgets/): cap tokens and cost for a print-mode session.
