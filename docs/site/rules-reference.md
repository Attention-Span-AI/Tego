---
title: Rules file fields
description: "Every field of a Tego rules file: its type, what it does, the default when it is missing, and the protection levels it works at, with examples."
summary: "Every field: type, meaning, default when missing, levels."
section: Reference
group: Rules file
order: 1
---

This page lists every field a rules file can hold. For each one it gives the type, what it does, what happens when the field is missing, and the [protection levels](/docs/tiers/) it works at. [Rules files](/docs/rules-files/) explains how the sections fit together, and [what a missing section allows](/docs/rules-files/#what-a-missing-section-means).

"All" in the Levels column means Basic, Plus and Max. A session started with `--observe` enforces nothing at any level.

```yaml
version: 0
name: my-agent
command: ["python3", "agent.py"]
extends: [tego/no-secrets]
fs:
  write: ["./src/", "./tests/"]
net:
  allow: ["api.example.com:443"]
exec:
  allow: ["python3", "git status"]
limits:
  wall: 2h
```

## How to write values

- Paths take `~/`, a relative path (from the folder where `tego run` starts) or an absolute path. Environment variables are not expanded, except `${TEGO_PROJECT_DIR}` inside `env.set`.
- Durations look like `30s`, `5m`, `2h`. Sizes use IEC units, such as `512MiB` or `4GiB`.

## Fields at the top of the file

| Field | Type | What it does | When missing | Levels |
|---|---|---|---|---|
| `version` | `0` | Format version. | Required. | All |
| `name` | lowercase letters, digits, `-`; up to 40 | The agent's name. Session names start with it. | Required. | All |
| `command` | list of strings | The agent's command line. `tego run ... -- <cmd>` replaces it. | Required. | All |
| `extends` | a name or a list of 1-8 | [Presets](/docs/presets/) or profiles merged under this file, left to right. | Nothing extended. | All |
| `revision` | string up to 64 | Your label for this version of the file. Top-level file only. | None. | All |
| `record` | `full`, `summary`, `off` | How much the record holds. `full` records every read. | `summary` | All |
| `tier` | `auto`, `landlock`, `cgroup`, `bpflsm` | Pins the level: Basic (`landlock`), Plus (`cgroup`), Max (`bpflsm`). Plus and Max need root. [How Tego picks a level](/docs/tiers/#how-tego-picks-a-level) covers a level the machine can't give. | `auto`: the highest level the machine allows. | All |
| `capture` | `auto`, `uprobe`, `forwarder`, `off` | How Tego sees model traffic. `uprobe` (kernel probes on the agent's TLS library) needs Plus or Max. | `auto`: the best the level allows. Basic uses `forwarder`. | All |
| `harness` | `auto`, `claude-code`, `codex`, `generic`, `none` | Which agent setup Tego prepares. | `auto`: read from `command`. | All |
| `io_uring` | bool | Allows io_uring, the kernel's batched input and output interface. Cannot be combined with `ask:`. | `false`: io_uring calls fail. | All |
| `keyring` | bool | Allows `add_key`, `request_key` and `keyctl`, the calls to the kernel keyring (the kernel's store for keys and tokens). | `false`: refused with EPERM. | All |
| `ipc` | bool | Allows System V IPC: shared memory, semaphores and message queues between processes. | `false`: refused with EPERM. | All |
| `setuid` | bool | Lets setuid programs gain privilege. | `false` | Plus, Max |
| `host_sockets` | bool | With no `net:` section, lets the agent reach unix sockets on the host. No effect beside a `net:` section. A preset cannot set it. | `false`: only the session's own sockets. | All |
| `keep_descendants` | bool | The session keeps running while processes the agent started are alive. | `false`: they are stopped with the agent. | All |
| `learn` | `{run, withheld}` | Written by `tego rules learn`: addresses held back after a secret read. A note only; it never allows anything. Top-level file only. | None. | All |

<a id="fs"></a>

## Files (`fs`)

Rules for files. The [built-in refusals](/docs/built-in-refusals/) apply with or without this section.

| Field | Type | What it does | When missing | Levels |
|---|---|---|---|---|
| `fs.write` | list of paths | Folders and files the agent may change: write, create, delete, rename, link, make folders. | Every write refused. `chmod` is never refused. | All |
| `fs.deny_read` | list of paths | Extra paths the agent cannot read. Globs expand when the rules are checked. A path that does not exist is reported `path-missing`. | The built-in secret list. `[]` switches it off. | All |
| `fs.ask` | up to 256 exact paths | Writes, creates, deletes and renames here wait for a person. Never asked under an `fs.write` path. See [Approvals](/docs/approvals/). | None. | All |
| `fs.ask_read` | up to 256 exact paths that exist | Reads here wait for a person. | None. | Basic only |
| `fs.watch` | list of paths that exist | Reads here are recorded one by one. At Basic this needs `record: full`. | None. | All |
| `fs.deny_write` | list of exact paths | Paths under an `fs.write` folder the agent cannot change. Adds to the built-in set. | The built-in set. | All. Best effort at Basic, and at Plus when Plus runs without its kernel hooks (`bpf.plane` finds neither `lsm` nor `fmod_ret`). |
| `fs.assurance` | `best-effort`, `kernel` | `kernel`: refuse to start (exit 125) where the kernel cannot hold `fs.deny_write`. | `best-effort` | `kernel` needs Plus or Max |
| `fs.reads` | `auto`, `held`, `direct` | `held` makes Tego check each read open, so a secret inside a write folder stays refused. `direct` only in the top-level file. | `auto`: held at Basic while a `deny_read` path lies inside a write folder. | All |
| `fs.apparmor_assume_root_namespace` | bool | For administrators: states that the session sees the root AppArmor policy namespace. Top-level file only. | `false` | All |

<a id="net"></a>

## Network (`net`)

Rules for the network.

| Field | Type | What it does | When missing | Levels |
|---|---|---|---|---|
| `net.allow` | list of endpoints | Places the agent may connect to: `host:port`, `cidr:port`, `tcp://` or `udp://` with a host and port, `unix:/path`, `unix:@name`. A host name never matches loopback, link-local, metadata or multicast addresses. | Every connection refused. | All |
| `net.ask` | up to 256 endpoints | Connections here wait for a person. `udp://` and `unix:` entries need `ask.hold: connect`. | None. | All |
| `net.listen` | up to 256 entries | Listening sockets the agent may open. | No TCP listener inside a `net:` section. | All |
| `net.ingress` | list of `{from, to}` | Inbound connections the session accepts. | None. | Plus, Max |
| `net.limits.connections` | integer | Most open connections. | No limit. | Plus, Max |
| `net.limits.pending_connects` | integer | Most connections in progress. | No limit. | Plus, Max |
| `net.limits.datagrams_per_second` | integer | Datagram rate. | No limit. | Plus, Max |
| `net.limits.bytes` | size | Byte budget. | No limit. | Plus, Max |
| `net.assurance` | `best-effort`, `kernel` | `kernel`: refuse to start where the kernel cannot decide each connection. | `best-effort` | `kernel` needs Plus or Max |
| `net.http` | list of `{host, allow, methods}` | Allowed URL path prefixes and methods for model traffic. Needs `capture: forwarder`. | None. | All |

### Name lookups (`net.dns`)

| Field | Type | What it does | When missing |
|---|---|---|---|
| `net.dns.mode` | `system`, `broker`, `off` | `system`: the machine's resolver is reachable on port 53. `broker`: Tego answers DNS. `off`: no DNS. | `system` |
| `net.dns.allow` | list of names | Names the broker answers. Needs `broker`. | None. |
| `net.dns.types` | list | Record types the broker answers. Needs `broker`. | None. |
| `net.dns.max_stale` | duration up to `24h` | Keep a resolved address allowed past its TTL. | Unset. |
| `net.dns.max_parallel` | 1-16 | Broker queries at once. | `8` |
| `net.dns.cache` | 0-512 | Broker cache entries. | `128` |

### Model traffic (`net.proxy`)

These fields shape model traffic through Tego's forwarder. They need a `models:` entry and `capture: forwarder`.

| Field | Type | What it does | When missing |
|---|---|---|---|
| `net.proxy.http2` | bool | Allows HTTP/2. | `false` |
| `net.proxy.websocket` | list of `{host, allow, methods}` | Allowed WebSocket routes. | None. |
| `net.proxy.connect` | list | Allows CONNECT tunnels to a declared model host. Cannot be combined with `net.http`, and disables `tokens`, `cost_usd` and `repeats`. | None. |
| `net.proxy.max_streams` | 1-128 | Streams per connection. | `32` |
| `net.proxy.max_tunnel_bytes` | size | Bytes per tunnel. | `16MiB` |
| `net.proxy.max_frame_bytes` | size | Bytes per frame. | `1MiB` |
| `net.proxy.tunnel_idle` | duration | Idle time before a tunnel closes. | `30s` |
| `net.proxy.tunnel_wall` | duration | Longest tunnel life. | `5m` |

<a id="exec"></a>

## Programs (`exec`)

Rules for programs.

| Field | Type | What it does | When missing | Levels |
|---|---|---|---|---|
| `exec.allow` | list | Programs that may run: a path, a name, a folder, or a command with arguments such as `git status`. | Any program. `exec: {}` runs only the agent's `command`. | All. Commands with arguments are best effort at Basic. |
| `exec.deny` | list | Programs or commands that are refused. With `deny` and no `allow`, everything else runs. | None. | All |
| `exec.ask` | list | Never asks: every match is refused. Use `exec.deny` to say what you mean. | None. | All |
| `exec.anonymous` | bool | Allows running programs from memory (memfd, a file that exists only in memory). | `false` | All |
| `exec.assurance` | `best-effort`, `kernel` | `kernel`: refuse to start where the kernel cannot pin which programs run. | `best-effort` | `kernel` needs Plus or Max |

[Testing rules](/docs/testing-rules/) shows how to check a command rule with `tego rules check --exec`.

## Environment variables (`env`)

The agent's environment. Tego applies `pass`, then `deny`, then `set`.

| Field | Type | What it does | When missing |
|---|---|---|---|
| `env.pass` | list of names | Only these variables reach the agent. `[]` passes none. | The whole environment passes. `tego rules check` warns `secret-env` when a variable looks like a credential. |
| `env.deny` | list of names | Removes these variables, even when passed. | None. |
| `env.set` | map of name to value | Sets variables. `${TEGO_PROJECT_DIR}` expands here. Variables Tego sets for the session win. | None. |

## Time and resource limits (`limits`)

Each limit ends or slows the session. A rules file can lower a [machine settings](/docs/machine-settings/) ceiling, never raise it. Limits work at every level. [Budgets](/docs/budgets/) covers `tokens` and `cost_usd`.

| Field | Type | What it does | At the limit |
|---|---|---|---|
| `limits.wall` | duration | Longest session time. | Ends, exit 124 |
| `limits.stall_after` | duration | Ends a session with no activity for this long. At Basic, reads are not activity under `record: summary` or `off`. | Ends, exit 124 |
| `limits.repeats` | integer | The same tool call this many times in a row. Needs model traffic metering. | Ends, exit 124 |
| `limits.tokens` | integer | Model tokens, input plus output. Needs metering, or the session does not start (125, `budget-unmetered`). | Ends, exit 124 |
| `limits.cost_usd` | number | Model cost from the price table. Needs metering and a price table. | Ends, exit 124 |
| `limits.memory` | size | Memory cap. | Killed, exit 137 |
| `limits.memory_high` | size | Memory level where the kernel starts slowing the agent. | Slowed |
| `limits.pids` | integer | Most processes and threads. | Ends at a refused fork, exit 137 |
| `limits.cpu` | number of cores, 0.01 or more | CPU cap. | Slowed |
| `limits.cpu_weight` | 1-10000 | CPU share against other work. | Slowed |

## Questions for a person (`ask`)

How actions held by `fs.ask`, `fs.ask_read`, `net.ask` and MCP `ask` rules wait. [Approvals](/docs/approvals/) explains the flow.

| Field | Type | What it does | When missing |
|---|---|---|---|
| `ask.timeout` | duration up to `1h` | How long an action waits for an answer. | `5m` (`4m` with `hold: request`) |
| `ask.on_timeout` | `refuse`, `refuse_always` | `refuse_always` also refuses the same action for the rest of the session. | `refuse` |
| `ask.max_pending` | 1-64 | Most actions waiting at once. | `64` |
| `ask.hold` | `connect`, `first_write`, `request` | Where a network ask waits: at connect, at the first write, or at the request. | `connect` |

`ask:` cannot be combined with `--observe`, `setuid: true` or `io_uring: true`.

## Risk scores (`gate`)

Scores that can only make an action stricter: allowed to asked, asked to refused.

| Field | Type | What it does | When missing |
|---|---|---|---|
| `gate.rules` | up to 256 entries of `<condition>: <0-100>` | Conditions: `fs.write outside worktree`, `fs.read matches <glob>`, `exec matches <command>`, `net to undeclared host`, `net to <host:port>`. Matching scores add up. | None. |
| `gate.thresholds.allow` | 1-99 | Scores below this are allowed. | `50` |
| `gate.thresholds.ask` | 2-100 | Scores from `allow` to this wait for a person; above it, refused. | `80` |
| `gate.completion` | `copied`, `held` | How a held file open completes. | `copied` |

## Changes during a session (`live`)

How the rules may change during a session. Top-level file only. [Live changes](/docs/live-changes/) explains both modes.

| Field | Type | What it does | When missing | Levels |
|---|---|---|---|---|
| `live.mode` | `locked`, `adjustable` | `locked`: rules can tighten during a session and loosen from the next one. `adjustable`: entries in the fence can be granted during the session. | `locked` | `adjustable` needs Plus or Max |
| `live.fence.read` | list | `fs.deny_read` entries that may be lifted. | None. | Plus, Max |
| `live.fence.net` | list | `host:port` entries that may be granted. | None. | Plus, Max |
| `live.fence.exec` | list | Absolute program paths that may be granted. | None. | Plus, Max |

The fence holds at most 64 entries in all.

## Telling the agent why (`reason`)

| Field | Type | What it does | When missing |
|---|---|---|---|
| `reason.reads` | `auto`, `on`, `off` | `on`: at Basic, every read open is reported to Tego, so a refused read of a secret is recorded. Each read is slower. | `auto` (off). |

[Refusals](/docs/refusals/) explains what the agent is told.

## MCP tools (`mcp`)

MCP (Model Context Protocol) servers the agent uses. [MCP tools](/docs/mcp-tools/) shows how to write tool rules.

| Field | Type | What it does | When missing |
|---|---|---|---|
| `mcp[].name` | lowercase letters, digits, `-`; up to 40 | The server's name. | Required. |
| `mcp[].command` | list of strings | A server the agent starts. Its program may run. | One of `command` or `url` is required. |
| `mcp[].url` | `http://` or `https://` URL | A server the agent connects to. Inside a `net:` section its host and port are allowed. | |
| `mcp[].tools.allow` | list of tool names | Tools the agent may call. When present, other tools are refused. | No tool rules. |
| `mcp[].tools.deny` | list of tool names | Tools that are refused. | |
| `mcp[].tools.ask` | list of tool names | Tools that wait for a person. Needs an `ask:` section. | |

A `tools:` key, even `tools: {}`, puts the server behind Tego's MCP relay. Tool rules cannot be used with `--observe`.

To set business rules for your MCP tools (`mcp[].business_rules`), email us at hello@attention-span.ai.

## Model providers (`models`)

Model endpoints. With an entry here, the agent's model traffic goes through Tego's forwarder, where it is counted.

| Field | Type | What it does | When missing |
|---|---|---|---|
| `models[].provider` | string | The provider's name. | Required. |
| `models[].host` | string | The model host. | Required. |
| `models[].port` | 1-65535 | The model port. | Required. |
| `models[].routes` | list of `{name, host, port, tls}` | Other backends you can switch this endpoint to during a session. `name` cannot be `direct`. See [Model routes](/docs/model-routes/). | None. |
| `models[].routes[].tls` | bool | `false` only for a plain-text server on this machine's loopback. | `true` |

With no `models:` entry, no forwarder starts.

## Fields Tego refuses

The schema accepts these fields, but Tego refuses a rules file that sets them to anything but empty:

| Field | Note |
|---|---|
| `prompt`, `skills`, `visibility` | Refused when not empty. |
| `docker` | Refused when not empty. |
| `containers` | Refused unless empty or `none`. |
| `exec.privileged` | Refused when not empty. |
| `env.mask` | Refused when not empty. |
| `credentials` | Refused by `tego rules check`. Pass credentials with `env.pass` or `env.set`. |

## Next steps

- [Rules files](/docs/rules-files/): how the sections fit together.
- [Presets](/docs/presets/): what each preset sets.
- [Testing rules](/docs/testing-rules/): check a rules file before a session.
