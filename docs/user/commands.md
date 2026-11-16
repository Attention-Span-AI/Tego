# Tego's commands

Tego's everyday commands follow one pattern: `tego <verb> <thing> [name] [flags]`, as kubectl does. The things are
**agents** (an agent you supervise, its project and its rules), **sessions** (one run of an agent under Tego),
**approvals** (an action a session holds until you answer) and **presets** (ready-made rules). `tego --help` shows
them grouped. Every older command still works as before; the table at the end says which new command does the same.

## Get started

| Command | What it does |
|---|---|
| `tego start` | Sets up your first agent, one question at a time: the agent, its sign-in, its project and its rules. It ends with the command that starts your first session. On a Mac it runs inside Tego's Linux VM and leaves you there. |
| `tego doctor` | Checks what this computer supports. |

## Agents

An agent is a rules file in `~/.config/tego/agents/<name>.yaml`: the program Tego starts, the project it works in and
what it may read, change and connect to.

| Command | What it does |
|---|---|
| `tego add agent [<name>] --project <folder> [--program claude-code\|codex\|<command>] [--preset base-development\|read-only-review] [--allow-host <host>]...` | Adds an agent for Tego to supervise. The name defaults to the project folder's name. It never replaces an agent of the same name. |
| `tego apply -f <file.yaml> [--name <name>]` | Adds or updates an agent from a rules file you wrote. The file is checked first; a file that doesn't compile changes nothing. |
| `tego get agents` | Lists your agents: name, project, presets and running sessions. |
| `tego describe agent <name>` | Says in plain words what the agent may change, never reads and may connect to. |
| `tego edit agent <name>` | Opens the rules file in `$EDITOR`, then checks it. |
| `tego remove agent <name>` | Stops supervising the agent: removes its rules file, after asking. `--yes` skips the question. |

## Sessions

A session is one run of an agent under Tego. Its name is the agent's name and four characters, such as
`tego-sample-dzfa`; any command below takes the name or the run id.

| Command | What it does |
|---|---|
| `tego run <agent>` | Starts a session. Run it from the agent's project folder. |
| `tego get sessions` | Lists sessions: name, agent, status, age and how many actions Tego blocked. |
| `tego describe session <name>` or `--last` | What the session did and what Tego blocked. |
| `tego logs <session> [-f]` | The session's events, as they happen with `-f`. |
| `tego stop`, `tego pause`, `tego resume <session>` | Control a running session. |

## Approvals

| Command | What it does |
|---|---|
| `tego get approvals` | Actions waiting for your answer. |
| `tego allow <approval>`, `tego deny <approval>` | Answer one. |

## Presets

| Command | What it does |
|---|---|
| `tego get presets` | Lists the presets. |
| `tego describe preset <name>` | What a preset allows and blocks. See [presets.md](presets.md). |

## Dashboard

| Command | What it does |
|---|---|
| `tego dashboard` | Opens the dashboard in your browser. On a Mac it runs the dashboard in Tego's VM and opens it on the Mac. |

## The older commands

They work as they always have. Where a newer command does the same, both names work.

| Older command | Same as |
|---|---|
| `tego status` | `tego get sessions` |
| `tego receipt` | `tego describe session` |
| `tego events` | `tego logs` |
| `tego approve`, `tego ask` | `tego allow`, `tego get approvals` |
| `tego init --agent`, `tego init --preset` | `tego add agent` (writes the rules file into the project as `agent.yaml`) |
| `tego setup` | in a terminal, the same guide as `tego start`; with `--json` or `-v`, the checklist |
| `tego serve` | `tego dashboard` |

The rest, for checking rules, recording, live control, tools for agents and records, are listed under "More commands"
in `tego --help`: `compile`, `test`, `drift`, `measure`, `watch`, `adopt`, `agents`, `learn`, `block`, `unblock`,
`rule`, `lift`, `grant`, `alternate`, `dns`, `mcp`, `route`, `gc`, `restore`, `rules`, `version` and `licenses`.
