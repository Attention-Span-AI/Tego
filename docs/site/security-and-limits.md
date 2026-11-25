---
title: Security and limits
description: "What Tego protects against, what it does not stop, what runs as root, what it keeps and sends, and how to report a security vulnerability privately."
summary: "What Tego stops, what it does not, and how to report a flaw."
section: Production
order: 5
---

Tego holds an AI agent to its rules file, whether the agent makes a mistake or a prompt injection has turned it. The rules cover the files it may read and write, the network hosts it may reach and the programs it may start. The Linux kernel and Tego's supervisor enforce the rules from outside the agent, so the agent cannot talk its way past them. Read this page before you rely on Tego: it lists what Tego does not stop.

Tego never calls a model and never answers for the agent. It refuses, and it records.

## What Tego does not stop

### Data leaving through a host you allow

- **Every allowed host is a way out.** A rule matches a host and port, not what the connection carries. An allowed model API and an allowed `github.com` can each carry anything the agent can read. Tego is not data-loss prevention. Allow as few hosts as the task needs, and keep secrets unreadable: what the agent cannot read, it cannot send.
- **Actions inside a service are invisible.** What the agent does inside a SaaS product or a managed database shows only in that service's own logs.

### What an allowed program does

- **An allowed interpreter can do anything in its own memory.** Allowing `python3` lets Python start. Tego does not see what the Python code then does inside its own process.
- **Tego limits only what the rules file names.** [Rules files](/docs/rules-files/#what-a-missing-section-means) says what a missing section allows.
- **At Basic, some checks happen outside the kernel.** Tego's supervisor decides command rules, protected-write targets and UDP destinations from its own copy of the system call's arguments. A hostile agent with a racing thread can change the arguments after the check. TCP connections are not open to this: the supervisor makes them itself. At Plus and Max the kernel decides network connections. [Protection levels](/docs/tiers/) compares the levels.

### What the agent can see

- **Tego does not hide the machine.** The agent can read any path your rules and the [built-in refusals](/docs/built-in-refusals/) do not refuse. A secret in a file neither names, or a token your shell exports, is open to it. [Secrets](/docs/secrets/) shows how to keep keys out.
- **File names stay visible.** At Basic and Plus, the agent can list the names of the files inside a folder under `fs.deny_read`, though it cannot read them.
- **The agent can read the network setup**: interface names and addresses, routes, and nearby machines it has talked to.
- **`host_sockets: true` opens local daemon sockets**, which can include your desktop session's.

### File aliases and mount limits

A file can have more than one name: a bind mount, a container volume or WSL's `/mnt/wslg/distro` shows the same file under another path. When a session starts, Tego reads the mount table and applies every file rule to each name the table gives that file. A rules file Tego cannot hold this way fails to start, and the error names the file and its other name. Two cases stay outside these rules:

- **Separate file system instances.** A second network mount of the same export, a FUSE mirror or a loop image shows the same data through a different file system. Tego does not know it is the same file. Deny that path too, or do not mount the data twice where the agent can read it.
- **Mounts made after the session starts.** Tego reads the mount table once, before the session. A mount that appears later is covered from the next session.

### Where it runs

- **Linux only.** On macOS and Windows, Tego and the agent run inside a Linux VM. In WSL, your Windows drives under `/mnt` are readable unless your rules deny them. [Supported systems](/docs/supported-systems/) lists each platform.
- **One machine at a time.** Tego has no view across machines.
- **Nothing can mount inside a session.** Rootless podman, bubblewrap, `unshare -m` and sandboxes an agent starts for itself fail, so Claude Code's and Codex's own sandboxes run switched off under Tego. `sudo` and other setuid programs (programs that run with their owner's rights, such as root's) do not work inside a session either.

### MCP tool rules

[MCP tool rules](/docs/mcp-tools/) decide by tool name, never by the call's arguments: you cannot allow `read_file` only under `src/`.

An agent that can attach a debugger to its own processes can go around Tego's MCP relay, the process that checks each tool call. At the `ptrace_scope` values Basic needs, 0 or 1, the agent can attach to the relay it started. [Servers and CI runners](/docs/servers-and-ci-runners/#process-inspection-setting-ptrace-scope) lists what each value allows.

### Changes to the record

The record is tamper-evident against the agent, not against the person who started the session. [Sessions and records](/docs/sessions-and-records/) explains what it proves.

## What runs as root

Only what you start with `sudo` runs as root. The installer sets up no root service, and Tego has no root daemon.

| What you run | Runs as root? |
|---|---|
| `tego run` at Basic, `tego watch` | No |
| `sudo "$(command -v tego)" run`, for Plus and Max | Yes: the launcher, for the whole session. The agent runs as you. |
| The timer that removes the kernel programs after a Plus or Max session | Yes, until the programs have been idle for `bpf.linger`, 5 minutes by default |
| `sudo tego agents`, `sudo tego adopt` | Yes, while they run |
| The dashboard | Never. It refuses to start as root. |

Granting `sudo` for `tego` is granting root. A sudoers rule limited to `tego` is not a boundary Tego supports.

Tego's trusted code is the launcher, the supervisor, the kernel programs and their loader, and the parsers that read the agent's traffic. The supervisor reads another process's memory, so a bug there could let a local user gain root. The code has fuzz tests, which feed it large amounts of random input. No one outside the project has reviewed it yet.

<span id="the-dashboard"></span>

## Who can use the dashboard

The dashboard answers only the user who started it. Other local users are refused. A change sent from inside a session, such as an approval or a rules change, is refused. [Dashboard](/docs/dashboard/) shows how to open it.

## What Tego keeps and sends

- **Sent:** nothing of yours. Tego has no telemetry, no update check, no crash reports and no usage metrics. Its own network traffic is DNS lookups of the hosts your rules name, and the connections it makes on the agent's behalf, such as the model forwarder's.
- **Downloaded when you agree:** `tego start` downloads an agent's installer, such as Claude Code's, when you say yes.
- **Kept:** each session's record, in a folder only you can open. By default it holds no request or response bodies. With `record: full`, it stores the model's requests and responses, which can include code and anything the agent read. Credential headers such as `authorization` and `x-api-key` are never stored. [Sessions and records](/docs/sessions-and-records/) covers where records live and how long.
- **Kept if you choose:** a login you save in `tego start` goes into `~/.config/tego/agent.env`, and a line in `~/.bashrc` loads it into every new shell. Any program you start from that shell can read it.

## Report a vulnerability

Report it privately with [Report a vulnerability](https://github.com/Attention-Span-AI/Tego/security/advisories/new) on the Tego repository. Do not open a public issue, pull request or discussion.

Say what you did, what you expected and what happened. Include the output of `tego version` and `tego machine check`, your kernel and distribution, and a rules file that reproduces it with any secrets removed.

No response time is promised. The project answers reports it can reproduce, and credits you if you want. The limits on this page are not vulnerabilities by themselves. A report that shows a limit is worse than this page says, or can be used from outside it, is in scope.

## Next steps

- [Protection levels](/docs/tiers/)
- [Secrets](/docs/secrets/)
- [Sessions and records](/docs/sessions-and-records/)
- [Supported systems](/docs/supported-systems/)
