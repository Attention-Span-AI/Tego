---
title: Presets
description: "The four Tego presets, no-secrets, no-prod, repo-only-writes and ci, and exactly which rules file fields and values each one sets."
summary: "The four presets and exactly what each one sets."
section: Reference
group: Rules file
order: 2
---

A preset is a small rules file that ships inside Tego. Tego has four: `tego/no-secrets`, `tego/no-prod`, `tego/repo-only-writes` and `tego/ci`. You add them to a rules file with `extends:`, and [Rules files](/docs/rules-files/) explains how their lists combine with yours.

This rules file extends the first three presets and adds what each one leaves for you to name: the folders the agent writes, the hosts and model it reaches, and the variables it gets:

```yaml
version: 0
name: my-agent
extends: [tego/no-secrets, tego/no-prod, tego/repo-only-writes]
command: ["claude"]
models:
  - {provider: anthropic, host: api.anthropic.com, port: 443}   # the model the agent calls
fs:
  write: ["./src/", "./tests/"]        # the folders repo-only-writes lets the agent write
net:
  allow: ["registry.npmjs.org:443"]    # the hosts no-prod lets the agent reach
env:
  pass: ["ANTHROPIC_API_KEY", "NPM_CONFIG_REGISTRY"]   # variables no-secrets would otherwise keep out
```

`tego/<name>` is the newest revision of a preset. `tego/<name>@<n>` pins revision `n`. Every preset is at revision 1. A released revision never changes; a change ships as a new revision.

`tego rules create --preset no-secrets,no-prod,repo-only-writes` writes a rules file from presets. The "Base development" choice in `tego start` uses the first three.

## Keep secrets out (`tego/no-secrets`)

Keeps secret environment variables away from the agent. It sets `env.pass`, so only these variables reach the agent:

```yaml
env:
  pass:
    - PATH
    - HOME
    - USER
    - LOGNAME
    - SHELL
    - LANG
    - LANGUAGE
    - LC_ALL
    - LC_CTYPE
    - LC_MESSAGES
    - TERM
    - COLORTERM
    - TZ
    - NO_COLOR
    - GOPATH
    - GOROOT
    - GOCACHE
    - GOMODCACHE
    - CARGO_HOME
    - RUSTUP_HOME
    - JAVA_HOME
    - NVM_DIR
    - PYENV_ROOT
    - VIRTUAL_ENV
    - CONDA_PREFIX
```

A variable such as `GITHUB_TOKEN` or `AWS_SECRET_ACCESS_KEY` stays out. To pass a variable your agent needs, add it to your own `env.pass`.

The preset adds nothing to `fs.deny_read`. Secret files are refused by the [built-in refusals](/docs/built-in-refusals/), which every rules file has unless it sets `deny_read: []`.

## Only hosts you name (`tego/no-prod`)

Refuses every network connection except to hosts your rules file names:

```yaml
net:
  allow: []
```

Add the hosts the agent needs to your own `net.allow`. The agent's model is reached only when your rules file lists it under `models:` or in `net.allow`. The machine's DNS resolver stays reachable, because `net.dns.mode` defaults to `system`.

## Only folders you name (`tego/repo-only-writes`)

Refuses every write outside the folders your rules file names:

```yaml
fs:
  write: ["/dev/null"]
```

`/dev/null` is there because many tools open it for writing. Add your project folders to your own `fs.write`, such as `./src/` and `./tests/`. With no folder of your own, every write but `/dev/null` is refused.

## CI runners (`tego/ci`)

For agents in CI. It records refused reads, keeps CI tokens out of the agent's environment, and refuses writes to `.github/`, best effort at Basic:
```yaml
reason:
  reads: on
env:
  deny:
    - ACTIONS_ID_TOKEN_REQUEST_URL
    - ACTIONS_ID_TOKEN_REQUEST_TOKEN
    - ACTIONS_RUNTIME_TOKEN
    - ACTIONS_RUNTIME_URL
    - ACTIONS_CACHE_URL
    - ACTIONS_RESULTS_URL
    - ACTIONS_CACHE_SERVICE_V2
    - GITHUB_TOKEN
    - GH_TOKEN
    - SIGSTORE_ID_TOKEN
    - INPUT_TOKEN
    - INPUT_GITHUB_TOKEN
fs:
  deny_write: ["./.github/"]
```

`env.deny` adds up across presets and your rules file. Your `env.pass` cannot bring a denied variable back: `tego rules check` warns `redundant-rule` that the passed name is removed again by `env.deny`. `env.set` of a denied variable is an error. The `.github/` path resolves from the folder where `tego run` starts, so run from the repository root. Your rules file can set `reason.reads` to another value. [CI](/docs/ci/) shows the preset in a workflow.

### What the CI preset does not cover

Three names on the list are recalled, to verify on a runner before you rely on them: `INPUT_TOKEN` and `INPUT_GITHUB_TOKEN`, because an action's input variable names depend on the action, and `ACTIONS_CACHE_SERVICE_V2`, which is a cache setting, not a credential. Secrets under other names need your own `env.pass` list or `tego/no-secrets`.

A hyphenated name such as `INPUT_GITHUB-TOKEN` cannot be denied by any rules file. Environment rule names take only letters, digits and underscores, and GitHub keeps the hyphen of an action input named `github-token`. To keep it from the agent, the action that starts Tego must scrub it from the environment, or your rules file must list the variables it allows in `env.pass` and leave that name out.

The `.github/` refusal is best effort at Basic: Tego's supervisor checks the path name, and an agent that swaps the path during the check can get past it. [Rules file fields](/docs/rules-reference/) lists the levels where `fs.deny_write` holds in the kernel. Keep write grants to folders such as `src/` and `tests/`. When `.github/` sits beneath a write grant and your rules file sets `fs.assurance: kernel`, a rules file pinned to Basic (tier landlock) fails `tego rules check` with `unenforced`, and a session at Basic, or at Plus without its kernel hooks, is refused before the agent starts.

The runner's command files named by `GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STATE` and `GITHUB_STEP_SUMMARY`, and stdout workflow commands (lines such as `::error::` that a step prints), are not protected by this preset. An agent that writes them can change a later step's environment, `PATH`, outputs, saved state or job summary. Removing a variable from the environment does not refuse access to its file. The action that runs the agent must keep those files out of the agent's write grants and filter workflow commands from the agent's output. GitHub lists the commands in its [workflow commands reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands).

## Next steps

- [Rules files](/docs/rules-files/): how presets combine with your own rules.
- [Rules file fields](/docs/rules-reference/): every field a preset can set.
- [Built-in refusals](/docs/built-in-refusals/): what every session refuses without a preset.
