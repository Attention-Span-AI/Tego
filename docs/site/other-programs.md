---
title: Other programs
description: "Run any program under Tego: a Python or Node agent, a browser agent or a plain script. Write its rules file, then list the programs and hosts it needs."
summary: "Run any agent, script or program under a rules file."
section: Agents
order: 3
---

Tego runs any program under a rules file, not only Claude Code and Codex. Write a rules file with `tego rules create`, name the programs the agent may start in `exec.allow` and the hosts it may reach in `net.allow`, then start it with `tego run`.

## Write a rules file

Pick one of three ways:

- **`tego start`**, then **Another program**, and type the command that starts it, such as `python3 bot.py` ([Quickstart](/docs/getting-started/)).
- **`tego rules create`** with no flags writes a starter `agent.yaml` for a Python agent (`python3 agent.py`) that you edit.
- **`tego rules create --preset`** builds the file from [presets](/docs/presets/) and your flags:

```sh
tego rules create --preset no-secrets,no-prod,repo-only-writes \
  --command "node agent.js" --write out/ --allow-host api.openai.com
```

`--write` and `--allow-host` repeat. `--allow-host` also takes a group of hosts as `@<group>`; `tego rules create --list` prints the groups.

Not sure what the program needs? Record one session with `tego watch`, which refuses nothing, and let Tego write the rules file from it. [Learning rules](/docs/learning-rules/) shows how.

## Run it

```sh
tego run agent.yaml
```

`tego run` takes a rules file path or the name of a saved agent. It starts the file's `command`. To start a different command under the same rules, put it after `--`:

```sh
tego run agent.yaml -- python3 agent.py --task review
```

A command given after `--` is allowed to start for that session only.

## Which programs and hosts to allow

[Rules files](/docs/rules-files/#what-a-missing-section-means) says what a missing `exec:` or `net:` section allows. To hold the agent to a list:

```yaml
exec:
  allow: ["python3", "git"]     # every other program is refused
net:
  allow: ["api.github.com:443"] # every other host is refused
```

- **`exec.allow`** names the programs the agent may start. The program in `command` is allowed on its own. Add each tool the agent runs (`git`, `bash`, `make`, `npm`). An entry that ends in `/` allows every program in that folder, such as a virtual environment: `"./.venv/"`.
- **`net.allow`** names the hosts it may reach, as `host:port`. `net: {allow: []}` allows no host at all.

Every refused program and connection lands in the session's [record](/docs/sessions-and-records/), so `tego session show --last` tells you what to add.

## Python and Node agents

A Python or Node agent that calls a model through Anthropic's, OpenAI's or Google's SDK works best with the model in `models:` and `capture: forwarder`:

```yaml
command: ["python3", "agent.py"]
models:
  - {provider: anthropic, host: api.anthropic.com, port: 443}
capture: forwarder
net:
  allow: []                     # the model is reached through the forwarder
env:
  pass: ["PATH", "HOME", "ANTHROPIC_API_KEY"]
```

Tego runs a listener on this machine for each `models:` entry and points the SDK at it through the provider's variable: `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` and `OPENAI_API_BASE`, or `GOOGLE_GEMINI_BASE_URL`. Each model call goes through that listener and lands in the record. Do not also list the model host in `net.allow`: a direct connection goes around the listener, and `tego rules check` warns about it.

Pass the API key by name in `env.pass`. With an `env.pass` list, the agent gets only the variables named there and in its presets.

The Tego repository has ready rules files to start from:

- [`examples/agents/claude-agent-sdk.yaml`](https://github.com/Attention-Span-AI/Tego/blob/main/examples/agents/claude-agent-sdk.yaml): a Python agent on the Claude Agent SDK.
- [`examples/agents/anthropic-sdk-python.yaml`](https://github.com/Attention-Span-AI/Tego/blob/main/examples/agents/anthropic-sdk-python.yaml): a Python agent on the Anthropic Python SDK.
- [`examples/agents/langgraph.yaml`](https://github.com/Attention-Span-AI/Tego/blob/main/examples/agents/langgraph.yaml): a LangChain or LangGraph agent in a Python virtual environment.
- [`examples/agents/custom-agent.yaml`](https://github.com/Attention-Span-AI/Tego/blob/main/examples/agents/custom-agent.yaml): a Python agent that writes one folder and asks before writing another.

### LangChain and LangGraph agents

Tego has no adapter for LangChain or LangGraph and sees the agent as any other process. It holds and records what the agent's tools do to files, programs and hosts, the model calls that go through the forwarder, and the tools of an MCP server behind Tego's relay. A tool that is a Python function inside the agent's own process is not seen as a tool; only what it does is.

## Browser agents

A browser agent starts a browser and visits sites. Its rules file needs:

- The browser program in `exec.allow`.
- Every site it visits in `net.allow`, or no `net:` section if it may browse anywhere.
- A writable folder for the browser's profile, in `fs.write`.

Your own browser profiles (Chrome, Chromium, Firefox, Edge) are on the [built-in refusals](/docs/built-in-refusals/) list, so the agent cannot read your cookies or saved logins. Record one session with `tego watch` to see what the browser touches, then write the rules from it.

## Next steps

- [Learning rules](/docs/learning-rules/): get a rules file from one recorded session.
- [Testing rules](/docs/testing-rules/): check a rules file before you run it.
- [Rules file fields](/docs/rules-reference/): every field and its default.
