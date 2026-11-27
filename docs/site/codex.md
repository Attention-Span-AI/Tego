---
title: Codex
description: "Run OpenAI Codex under Tego with an API key or a ChatGPT login, with Codex's own sandbox off and its model calls recorded through Tego."
summary: "Run Codex under a rules file, with an API key or a ChatGPT login."
section: Agents
order: 2
---

To run Codex under Tego, write a rules file with `tego start` or `tego rules create --agent codex`, pass your OpenAI API key in `CODEX_API_KEY`, and start it with `tego run`. For a ChatGPT plan, start from the ready file `examples/agents/codex-chatgpt.yaml`.

## Codex's own sandbox stays off

Codex's built-in sandbox cannot start inside a Tego session, so every rules file for Codex turns it off and lets Tego's rules hold Codex instead. The files Tego writes start Codex as:

```text
codex --no-daemon --sandbox danger-full-access --ask-for-approval never exec
```

- `--sandbox danger-full-access` and `--ask-for-approval never` turn off Codex's sandbox and its own prompts. `ask:` rules in the rules file hold actions for a person instead ([Approvals](/docs/approvals/)).
- `--no-daemon` keeps Codex from handing its commands to a background server that runs outside the session.

## With an API key

From the project's folder:

```sh
export CODEX_API_KEY=<your key>
tego rules create --agent codex --write src/ --prompt "Fix the failing test in src/"
tego run agent.yaml
```

`tego rules create --agent codex` writes `agent.yaml` from the `no-secrets`, `no-prod` and `repo-only-writes` [presets](/docs/presets/) and adds what Codex needs:

```yaml
fs:
  write:
    - "./src/"           # --write
    - "./.tego/tmp/"     # TMPDIR: the agent's temporary files stay in the project
    - "./.tego/codex/"   # Codex config source; the forwarder creates the writable home for each run
    - "/dev/null"        # its tools redirect into it
    - "/dev/tty"         # the full-screen interface draws there
    - "/dev/ptmx"        # Codex runs each command in a pseudo-terminal
    - "/dev/pts/"        # the same pseudo-terminals
env:
  pass:
    - "CODEX_API_KEY"   # Codex exec with an API key
harness: codex
capture: forwarder
models:
  - {provider: openai, host: api.openai.com, port: 443}
```

Without `--write`, only `./out/` and Codex's own folders are writable.

Codex ignores `OPENAI_BASE_URL`, so Tego routes its model calls another way. For each session it writes a Codex home of its own in the session's private folder, `$XDG_RUNTIME_DIR/tego/<session>/codex/`. Its `config.toml` points Codex at Tego's forwarder. Every model call then goes through Tego and lands in the session's [record](/docs/sessions-and-records/). Tego removes the folder when the session ends.

This needs two things:

- **Start the session without `sudo`** (Basic). A session started as root gets no private folder, so Codex is not routed through the forwarder.
- **`XDG_RUNTIME_DIR` set** to an absolute folder only you can write. A login through systemd sets it to `/run/user/<uid>`. Without it, Tego refuses the session with exit code 125 and says how to fix it.

## With a ChatGPT login

The ChatGPT sign-in listens on a local port for your browser, which cannot work inside a session. Sign in once outside Tego, into a Codex home of its own, then start from [`examples/agents/codex-chatgpt.yaml`](https://github.com/Attention-Span-AI/Tego/blob/main/examples/agents/codex-chatgpt.yaml):

```sh
mkdir -p ~/.local/share/tego/codex-chatgpt
CODEX_HOME=~/.local/share/tego/codex-chatgpt codex login
printf 'sandbox_mode = "danger-full-access"\napproval_policy = "never"\ncheck_for_update_on_startup = false\n' \
  > ~/.local/share/tego/codex-chatgpt/config.toml
```

The file's header lists the lines to change: your home folder, and the folder of the `codex-code-mode-host` helper (`dirname "$(readlink -f "$(command -v codex)")"`). Run it from a project with `work/` and `held/` folders, and keep the rules file outside the project:

```sh
mkdir -p work/tmp held
tego run ~/rules/codex-chatgpt.yaml
```

With a ChatGPT login, Codex talks to `chatgpt.com`, so its model calls bypass Tego's forwarder. The rules file allows `chatgpt.com` and `auth.openai.com` by host. The connections are recorded; the content of the model calls is not.

## Your other sessions can read Codex's folder

While a Codex session runs, an agent in another of your Tego sessions can read its private folder, `$XDG_RUNTIME_DIR/tego/<session>/codex/`. That folder holds Codex's settings, its session history and, if you typed an API key into Codex's login screen, that key. No session can write it but its own.

If you type a key into Codex, run no other agent of yours meanwhile, or add this line to the other rules files:

```yaml
fs:
  deny_read: ["/run/user/<uid>/tego/"]
```

An agent under that rule cannot read its own last refusal through `$TEGO_REASON` either, since that file lives in the same folder.

## What Codex sees when Tego refuses an action

Codex gets the ordinary error and no note. [Refusals](/docs/refusals/#who-is-told-why) shows how a wrapper can read why.

## Next steps

- [Refusals](/docs/refusals/): what every agent sees when Tego refuses an action.
- [Secrets](/docs/secrets/): keep keys and `.env` files away from the agent.
- [Learning rules](/docs/learning-rules/): record one session and get a rules file from it.
