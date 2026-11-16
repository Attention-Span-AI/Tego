# Tego's commands

Tego's commands follow git's shape: a noun, then a verb (`tego session list`). `tego help` shows the common ones and
`tego help -a` every one. `tego help <command>`, or `tego <command> -h`, shows a command's usage and flags.

A **session** is one run of an agent under Tego. Its name is the agent's name and four characters, such as
`tego-sample-dzfa`; every command that takes a session takes its name or its run id. An **agent** is a rules file in
`~/.config/tego/agents/<name>.yaml`: the program Tego starts, the project it works in, and what it may read, change and
connect to.

## Get started

| Command | What it does |
|---|---|
| `tego start` | Sets up your first agent in four steps: the agent, its login, its project and its rules. Then it opens the dashboard and shows the command that starts your first session. On a Mac it runs inside Tego's Linux VM and leaves you there, in the project. |
| `tego dashboard` | Opens the dashboard in your browser. On a Mac it runs the dashboard in Tego's VM and opens it on the Mac. |

## Supervise an agent

| Command | What it does |
|---|---|
| `tego run <agent>` | Runs the agent under its rules. Run it from the agent's project folder. In a terminal it prints two lines, when the session starts and when it ends; `-v` prints everything. |
| `tego session list` | Lists sessions: name, agent, status, when it started and how many actions Tego blocked. |
| `tego session show <session>` or `--last` | Shows what the session did and what Tego blocked. |
| `tego session stop`, `pause`, `resume <session>` | Stops, pauses or resumes a running session. |

## Write the rules

| Command | What it does |
|---|---|
| `tego rules create [flags]` | Creates a rules file (`agent.yaml`) in a project, from presets. See [presets.md](presets.md). |
| `tego rules edit <agent \| file>` | Opens the rules file in `$EDITOR`, checks your edit, and saves it only when it passes. |
| `tego rules check <agent \| file>` | Checks a rules file and shows what it enforces. |
| `tego rules learn <session>` | Creates a rules file from what a session did. |

## Check this machine

| Command | What it does |
|---|---|
| `tego machine check` | Checks what this machine can enforce. |
| `tego machine test` | Runs Tego's self-check. |

## Everything else

`tego help -a` lists these by group:

- **Answer what a session asks:** `ask`, `approve`, `deny`, `alternate`.
- **Change a running session's rules:** `block`, `unblock`, `grant`, `lift`, `restore`, `rule`, `rules <session>`.
- **Read the record:** `events`, `drift`, `measure`, `status`, `gc`.
- **Supervise other programs:** `watch`, `adopt`, `agents`. `adopt` and `agents` need root: run them with sudo.
- **Tools for agents:** `mcp`, `route`, `dns`.
- **About Tego:** `setup`, `serve`, `version`, `licenses`.

## Older names

They work as they always have, with the same flags, output and exit codes.

| Older name | Same as |
|---|---|
| `tego init` | `tego rules create` |
| `tego compile` | `tego rules check` |
| `tego learn` | `tego rules learn` |
| `tego receipt` | `tego session show` |
| `tego stop`, `pause`, `resume` | `tego session stop`, `pause`, `resume` |
| `tego doctor` | `tego machine check` |
| `tego test` | `tego machine test` |
