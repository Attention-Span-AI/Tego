# maze

**Rules your AI assistant can't ignore.** Maze sets what Claude Code can do in your project: which files it
reads and changes, which programs it runs, which websites it reaches, and that it never pushes or publishes
as you. The rules are enforced by the operating system's kernel, not by asking the model nicely.

> **Status: preview.** `maze` sets up and saves your rules today. Enforcing them (`maze run`) is the next
> release, so for now Claude Code still runs without Maze. Every screen says so.

## Install

No release is published yet, so build it from a checkout of this repo. You need Go 1.27 or newer.

```sh
make maze
```

That installs `maze` into `$(go env GOBIN)`, or `~/go/bin` when that is unset. Put that folder on your `PATH`.

Check it worked:

```sh
maze system doctor
```

## Start

```sh
cd your-project
maze
```

Three short pages:

1. **Project.** Which folder Claude Code works in.
2. **Permission.** Maze asks once to read file names, `package.json`, Claude Code's settings and setting
   *names* (which settings exist, never their values). Nothing leaves your computer.
3. **Review.** Every rule, one line each, `✓ can` or `✗ can't`. Space switches a rule. Grey rows are fixed:
   Maze always enforces them (your `.env` files, key folders like `~/.ssh`, changes outside the project).

**Save rules** writes:

| File | What | Share it? |
|---|---|---|
| `.maze/workspace.yaml` | this project's rules | yes, commit it |
| `~/.maze/personal.yaml` | your rules for every project | no, it's yours |
| `.gitignore` | one line: `.maze/state/`, Claude Code's files during a run | yes |
| `.git/hooks/pre-push` | asks before you push commits Claude Code made under Maze | stays local |
| `~/.maze/agent/` | Claude Code's own commit-signing key | never leaves your computer |

If anyone changes `.maze/workspace.yaml` (you by hand, a teammate's commit, or an agent), the next `maze`
lists what changed (`+` added, `-` removed, `~` switched) and the rules you approved stay until you approve the
new ones. A file can't unlock a fixed rule: Maze puts it back and says so.

## Every day

```sh
maze status                         # one line: is this project set up and approved?
maze allow program make             # Claude Code can run make
maze allow website api.github.com   # it can connect to api.github.com
maze block file config/prod.json    # it can't read that file (one that exists)
maze block write                    # the project is read-only for it
maze workspace show                 # every rule for this project
maze help                           # all commands
```

`-C <dir>` works with every project command, `--json` with every command that reports something, and
`--no-color` everywhere. Each `allow` or `block` prints the command that undoes it.

## For scripts and CI

Every command ends with an exit code a script can check (`echo $?`):

| Code | Means |
|---|---|
| 0 | done |
| 1 | needs a person: the project isn't set up, its rules changed and wait for approval, or Maze refused a change |
| 2 | the command was typed wrong |
| 125 | Maze itself failed |

`--json` gives the same answers in a form a script can read.

## What Claude Code's commits look like

Under Maze, Claude Code commits as **Claude Code (via Maze)** `<claude-code@maze.local>`, signed with its own
key; your own commits and git config don't change. To list its commits:

```sh
git log --author=claude-code@maze.local
```

To check their signatures:

```sh
git -c gpg.ssh.allowedSignersFile=$HOME/.maze/agent/allowed_signers log --show-signature
```

The pre-push check lists the commits made with Maze's identity (the agent's author and committer email, or its
signing key) and asks before they leave your computer. It finds them by that identity, which the agent's
environment sets: an agent that sets its own git identity (`GIT_AUTHOR_EMAIL=you@example.com git -c
commit.gpgsign=false commit`) makes commits it does not list. What stops the agent pushing is that it has no
login to push with (your tokens and keys stay blocked); the check is the reminder for what you push yourself.
Pushing from an app with no terminal (VS Code, GitHub Desktop) stops with a message; review them in a terminal, or let the push through once with
`MAZE_ALLOW_AGENT_PUSH=1 git push`. If your hooks live elsewhere (husky), Maze prints the one line to add to your
own pre-push hook.

## Your Claude Code settings

If `.claude/settings.json` already has permission rules, Maze reads them during setup and shows how each one is
covered. A name rule like `Bash(git push*)` is easy to get around, so Maze enforces the effect behind it: Claude
Code can't push to GitHub as you. A deny wins over an allow, as in Claude Code. Rules from your own files
(`settings.local.json`, `~/.claude/settings.json`) are listed but never copied into the shared project file.
`maze init --explain` lists every rule and what covers it.

## Remove

```sh
maze workspace remove      # this project: .maze/, the pre-push check, Maze's .gitignore line
maze profile remove        # your rules for every project
rm -rf ~/.maze             # everything else Maze keeps, the signing key included
rm "$(command -v maze)"    # the program itself
```
