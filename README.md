<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/tego-logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/tego-logo.svg">
    <img alt="Tego" src="docs/assets/tego-logo.svg" width="280">
  </picture>
</h1>

<p align="center"><strong>Tego limits what any AI agent can touch on Linux, and records every run.</strong></p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <a href="docs/INSTALL.md"><img alt="Go 1.27" src="https://img.shields.io/badge/go-1.27-00ADD8?logo=go&amp;logoColor=white"></a>
  <a href="docs/TIERS.md"><img alt="Platform: Linux" src="https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&amp;logoColor=black"></a>
  <a href="docs/CHANGELOG.md"><img alt="Release: v0.1.3" src="https://img.shields.io/badge/release-v0.1.3-F26327"></a>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> &nbsp;·&nbsp;
  <a href="#how-it-works">How it works</a> &nbsp;·&nbsp;
  <a href="#documentation">Docs</a> &nbsp;·&nbsp;
  <a href="#known-limits">Known limits</a> &nbsp;·&nbsp;
  <a href="#contributing">Contributing</a> &nbsp;·&nbsp;
  <a href="#security">Security</a>
</p>

Tego runs any AI agent that is a Linux process (an MCP server, a Python worker, a CI job that calls a model, a 24/7 assistant, your own agent, or a coding tool such as Claude Code) under a short written contract listing the files, programs and hosts it may use. The Linux kernel and Tego's supervisor enforce it from outside the agent, pause chosen file opens and connections until a person answers, and keep a hash-chained record of each run, with no AI model inside Tego.

It refuses what the contract rules out (files, programs, network hosts), can pause a file open or a connection until
you answer, and keeps a hash-chained record of each run. What that record holds depends on the tier: by default, tier 1
records programs, writes and connections, and no file reads.

The agent is an ordinary process: Tego does not need to know what it is, and it never calls a model itself.

**Why it exists.** An AI agent runs as you, next to your keys and your network, and a mistake or a prompt
injection can reach all of them. Rules that live inside the agent hold only while the agent follows them, so Tego keeps
them outside it, and a prompt-injected or mistaken agent cannot talk its way past them.

> [!IMPORTANT]
> Tego limits only what the contract names, and each tier has limits of its own. Read
> [Known limits](#known-limits) and [docs/GAPS.md](docs/GAPS.md) before you rely on it.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/dashboard-overview-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/dashboard-overview-light.png">
    <img alt="The Tego dashboard's Overview page, showing one run that leaked secrets and four blocked actions" src="docs/assets/dashboard-overview-light.png" width="900">
  </picture>
  <br>
  <sub>The dashboard after the <a href="examples/supply-chain-demo/README.md">supply-chain demo</a>'s <code>backup</code> step, which runs the project's tests with no agent and fake secrets: one run only watched, one run protected.</sub>
</p>

## Features

This repository holds the engine, the `tego` command, the three enforcement tiers, a dashboard for one person on
their own machine, and the kernel programs.

| Feature | What you get |
|---|---|
| <img src="docs/assets/icons/scroll-text.svg" width="20" height="20" alt=""> **Contracts** | An unmodified agent process runs under a per-agent contract, a YAML file. `tego rules create` starts one from presets, `tego rules check` prints its rule table, and `tego rules learn` proposes one from a finished run. |
| <img src="docs/assets/icons/shield.svg" width="20" height="20" alt=""> **Enforcement outside the agent** | At every tier the kernel refuses writes and programs outside the contract. Hosts are decided by Tego's supervisor at tier 1 and by the kernel at tiers 2 and 3. |
| <img src="docs/assets/icons/hand.svg" width="20" height="20" alt=""> **Held actions** | An `ask` rule on a file or a connection holds it until you allow or deny it, with `tego approve`, `tego deny` or the dashboard. Held file reads (`fs.ask_read`) are tier 1 only, and `exec.ask` is reserved: it refuses. |
| <img src="docs/assets/icons/pause.svg" width="20" height="20" alt=""> **Live control** | `tego session pause`, `resume` and `stop`, and `tego block`, act on a running session. An [Adjustable](docs/user/live-modes.md) run (tiers 2 and 3, which need root) can also be loosened while it runs. |
| <img src="docs/assets/icons/link.svg" width="20" height="20" alt=""> **Hash-chained record** | Every run writes one. `tego session show` and `tego events` read it, `tego events <run> --verify` checks its chain, `tego drift` compares what was allowed with what was used, and the dashboard shows it. |
| <img src="docs/assets/icons/activity.svg" width="20" height="20" alt=""> **Run limits** | A run that passes its limits (tokens, cost, time, stall, repeats) ends with exit code 124. Token and cost limits count Anthropic Messages traffic only. |
| <img src="docs/assets/icons/eye.svg" width="20" height="20" alt=""> **Watch any agent** | `tego watch` runs any command as a black box and records it. `tego agents` lists the agents running here and `tego adopt` governs one already running; both need root. |
| <img src="docs/assets/icons/layout-dashboard.svg" width="20" height="20" alt=""> **Local dashboard** | `tego dashboard` serves runs, logs, refusals and held requests on `127.0.0.1`, for one person. |
| <img src="docs/assets/icons/server.svg" width="20" height="20" alt=""> **MCP tool rules** | A relay can allow, hold or deny single tools of an MCP server, and `tego mcp` changes that live ([guide](docs/user/mcp-tools.md)). |
| <img src="docs/assets/icons/ban.svg" width="20" height="20" alt=""> **Nothing sent home** | No telemetry, no update check, no crash reports. Runtime traffic includes DNS lookups and connections for the agent ([details](docs/OPERATIONS.md#tegos-own-network-traffic)); the setup guide also downloads an agent's installer when you agree, and start/dashboard commands make local dashboard probes. |

[examples/agents/](examples/agents/README.md) has contracts for Claude Code, OpenAI Codex, the Claude Agent SDK, the
Anthropic Python SDK and an agent of your own.

## Quickstart

### 1. Install

| System | Run | Then |
|---|---|---|
| **Linux** (amd64 or arm64) | `curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh \| sh` | If `tego` isn't found, run the `export PATH=…` line it prints, or log in again. |
| **macOS** 13.5 or later | the same line | Open a new terminal window. Tego runs in a small Linux VM ([Lima](https://lima-vm.io)), and the `tego` command on your Mac runs it there. |
| **Windows** | `wsl --install -d Ubuntu-24.04` in PowerShell | Open Ubuntu and run the Linux line there. |
| **From source** | `git clone https://github.com/Attention-Span-AI/Tego && cd Tego && make build` | [Build from source](docs/INSTALL.md#build-from-source) |

Run the same line again to update. On a Mac, that also updates Tego inside the VM.
[docs/INSTALL.md](docs/INSTALL.md) has the details, what each system was tested on, and how to check the installer
before it runs.

### 2. Set up

```sh
tego start
```

Four questions, one at a time:

1. **Agent:** Claude Code, Codex or another program. Tego offers to install Claude Code or Codex if it's missing.
2. **Login:** your Claude subscription or an API key, saved for later sessions if you want.
3. **Project:** a test project Tego makes for you, or one of yours.
4. **Rules:** Base development, Read-only review, rules you pick one by one, or your own rules file
   ([presets](docs/user/presets.md)).

It then opens the dashboard and prints the command for the next step. It never starts the agent for you.

### 3. Run your agent under the rules

```sh
cd ~/tego-sample && tego run tego-sample
```

Ask the agent to run the project's tests. The test project's dependency is poisoned on purpose, harmlessly: it tries to
read the project's `.env` and send it out. Tego blocks both, and the tests still pass.

```text
  ✓ Session tego-sample-6hbm ended · 2 actions blocked
      Details: tego session show tego-sample-6hbm
```

### 4. See what happened

```sh
tego session show --last      # what the session did, and each blocked action with its rule
tego dashboard                # the same session in your browser
```

### Commands you'll use

| To | Run |
|---|---|
| **Set up** another agent or project | `tego start` |
| **Open** the dashboard | `tego dashboard` |
| **Run** an agent | `tego run <agent>` |
| **List, show or stop** sessions | `tego session list` · `tego session show <session>` · `tego session stop <session>` |
| **Write** a rules file in a project | `tego rules create --preset no-secrets,repo-only-writes --write src/` |
| **Change** rules, checked before they're saved | `tego rules edit <agent>` |
| **Check** what a rules file enforces | `tego rules check <agent>` |
| **Narrow** rules to what a session used | `tego rules learn <session>` |
| **Check** this machine | `tego machine check` |

`tego help` lists the common commands, `tego help -a` every one, and [docs/user/commands.md](docs/user/commands.md)
explains each. [examples/agents/](examples/agents/README.md) has rules files for Claude Code, Codex, the Claude Agent
SDK, the Anthropic Python SDK and an agent of your own. [docs/QUICKSTART.md](docs/QUICKSTART.md) does each step by hand
and explains the output.

### If something's off

- **`tego: command not found`:** open a new terminal window, or run the line the installer printed last.
- **On a Mac:** keep your projects inside Tego's VM. No Mac folders are shared with it by default
  ([sharing one](docs/INSTALL.md#macos)). `tego shell` opens a shell in the VM.
- **Over SSH on Linux:** a run exits with code 125 until you start a shell in your user's cgroup:
  `systemd-run --user --scope bash` ([why](docs/INSTALL.md#check-the-machine)).

## How it works

```mermaid
flowchart LR
    contract["agent.yaml<br/>your contract"] -->|compiled to rule tables| supervisor
    supervisor["Tego supervisor<br/>a process outside the agent"] -->|starts it under the rules| agent["AI agent<br/>an unmodified process"]
    agent -->|system calls| kernel["Linux kernel<br/>Landlock, seccomp, BPF"]
    kernel -->|refuses writes and programs<br/>outside the contract| agent
    kernel <-->|tier 1: the supervisor decides hosts| supervisor
    supervisor -->|appends each event| ledger[("Hash-chained<br/>record")]
    ledger -->|reads| dashboard["Dashboard<br/>on 127.0.0.1"]
    dashboard -->|allow, deny, block, stop| supervisor

    style supervisor stroke:#F26327,stroke-width:3px
    style kernel stroke:#F26327,stroke-width:3px
```

1. `tego run` validates the contract and compiles it to rule tables for the tier your machine allows.
2. The supervisor starts the command inside its own cgroup, under those rules. A `claude` command started without root
   gets `--settings` with a per-run file, so that refusals reach the agent through a hook, and `--mcp-config` when the
   contract relays MCP servers; `harness: none` turns both off. Everything the agent forks or executes stays in the run.
3. What the contract rules out fails with an ordinary system call error. The agent is not asked to cooperate. At tier 1
   Tego's supervisor decides hosts, and at tiers 2 and 3 the kernel does.
4. Each event goes into the run's hash-chained record, which `tego session show`, `tego events` and the dashboard read.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) has the full design.

## Protection levels

| Tier | Needs | Gives |
|---|---|---|
| 1, `landlock` | Landlock ABI 2 or newer (Linux 5.19 or later, or RHEL 9's 5.14; tested from 6.1 and on RHEL 9), cgroup v2 with a subtree delegated to your user, no root | Landlock and a seccomp supervisor: file, program and network rules, held requests, a record of exec, write and connect, not of reads |
| 2, `cgroup` | root (`sudo`), Landlock ABI 2 or newer, cgroup v2, BTF | cgroup-attached BPF and fanotify: the kernel records reads too |
| 3, `bpflsm` | root, and `bpf` in the kernel's boot LSM list | Tier 2, with the decision plane running as BPF LSM hooks |

All three tiers are in the release binary and in the one `make build` produces. `tego machine check` says which tier your machine gets, and each
run records the tier it had. Details, including the one boot line Ubuntu needs for tier 3, are in
[docs/TIERS.md](docs/TIERS.md).

## Dashboard

`tego dashboard` starts a dashboard on `127.0.0.1` for one person, and prints its link (on a Mac, opens it in your browser): runs, logs, refusals, held requests you can allow or
deny, each run's rules, and a way to stop a run or block something while it runs. A run started with `sudo` is root's
until it ends, so the dashboard shows it only then; until then use `sudo "$(command -v tego)" status`.
`--preview` also lists the pages for MCP tool rules and model routes. See [docs/DASHBOARD.md](docs/DASHBOARD.md).

<table>
  <tr>
    <td width="33%"><img alt="Detections page" src="docs/assets/dashboard-detections.png"></td>
    <td width="33%"><img alt="Investigate page of a refused read of id_rsa" src="docs/assets/dashboard-investigate.png"></td>
    <td width="33%"><img alt="Run page of a protected run" src="docs/assets/dashboard-run.png"></td>
  </tr>
  <tr>
    <td align="center"><sub>Detections</sub></td>
    <td align="center"><sub>One refused read</sub></td>
    <td align="center"><sub>A protected run</sub></td>
  </tr>
</table>

## Known limits

The full list, with what to do about each, is in **[docs/GAPS.md](docs/GAPS.md)**. Read it before you rely on Tego.

- It does not stop what an allowed program does inside its own memory. If `python` is allowed, Python can do anything
  Python can do.
- It does not stop data leaving through a destination you allowed. Rules match `host:port`, not what the connection is
  used for, so an allowed model endpoint and an allowed `github.com:443` are equally open. Treat every allowed host as a
  way out.
- It does not hide the machine. The agent can read any path that is not in `deny_read`.
- It limits only what the contract names. With no `net:` section every IP destination is reachable, and with no `exec:`
  section every program runs.
- Not every rule is the kernel's at every tier. At tier 1 the supervisor, in user space, decides command rules and
  `deny_write` targets on its copy of the arguments, which is best effort: a racing thread of a hostile agent can change
  what the kernel then acts on. [spec/backend/CAPABILITIES.md](spec/backend/CAPABILITIES.md) lists each rule by tier.
- By default it does not record reads at tier 1. Under `record: summary`, the default, an allowed read leaves no line,
  and a read that `deny_read` refuses fails with `EACCES` and leaves no line either, unless the supervisor is told of
  reads: held reads (the default `fs.reads: auto` turns them on when a `deny_read` target lies inside a write entry),
  `reason.reads: on`, `fs.ask_read` or a read gate; then a refused read leaves one line. Where it leaves none, the read
  is still refused, but `tego run` can print `refused 0`, and `tego session show` says that no recorded action was refused
  and that the run does not record refused reads: a clean receipt there says nothing about reads. `record: full`
  records reads and makes every open slower. Tiers 2 and 3 record them without it.
- The record is tamper-evident against an agent held by a contract, within the mount and storage limits
  [docs/GAPS.md](docs/GAPS.md) lists, not against the person who started the run. A
  record-only run (`tego watch` with no `--boundary`, `tego run --observe`) has no Landlock rules, so its agent, which
  runs as you, can rewrite its own record.
- The MCP relay remains a preview feature (`--preview` lists its dashboard page). Its stdio gate pins the exact
  child before exec, but a run with ptrace or `pidfd_getfd` authority over the shim or server can write directly to
  the server socket, bypassing tool decisions and their ledger lines. It also recognises only the declared command
  spelling. Keep a forbidden capability out of any server the run can reach. See GAPS C50/C51 and the
  [proposed ADR 0126 amendment](docs/adr/0126-mcp-tool-rules.md#proposed-amendment-2026-11-03-preview-or-security-boundary).
- Linux only. On macOS and Windows, run it inside a Linux VM.

## Documentation

| | Read |
|---|---|
| **Start** | [Install](docs/INSTALL.md), [Quickstart](docs/QUICKSTART.md), [Tiers](docs/TIERS.md) |
| **Use** | [User guide](docs/user/README.md), [Dashboard](docs/DASHBOARD.md), [Example contracts](examples/agents/README.md), [Operations](docs/OPERATIONS.md) |
| **Trust** | [Known limits](docs/GAPS.md), [Capabilities by tier](spec/backend/CAPABILITIES.md), [Security policy](SECURITY.md) |
| **Design** | [Architecture](docs/ARCHITECTURE.md), [Specifications](spec/README.md), [Decision records](docs/adr/README.md) |
| **Change** | [Repository layout](docs/REPO-LAYOUT.md), [Versioning](docs/VERSIONING.md), [Changelog](docs/CHANGELOG.md) |

[docs/README.md](docs/README.md) is the full map, with a glossary.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) says how to build, test and send a patch. Everyone taking part follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Report a vulnerability through the private route in [SECURITY.md](SECURITY.md), not in a public issue. That page also
lists what Tego trusts and what is out of scope.

## License

[Apache-2.0](LICENSE). The kernel programs under `bpf/` are dual
[GPL-2.0-only / BSD-2-Clause](LICENSES/README.md) (ADR 0012). [Third-party notices](THIRD_PARTY_NOTICES.txt) cover
the dependencies and the dashboard's Lucide icons, which this page uses too.

Claude, Codex and other product names are trademarks of their owners; Tego is not affiliated with or endorsed by them.

Tego is made by [Attention Span](https://github.com/attention-span-ai).
