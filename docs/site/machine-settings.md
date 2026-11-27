---
title: Machine settings
description: "The machine config files Tego reads, in order, and the settings that apply to every session: ceilings, retention, ports and approvals."
summary: "The config files that set limits and defaults for every session on a machine."
section: Reference
group: Machine
order: 2
---

`/etc/tego/config.yaml` and `~/.tego/config.yaml` set ceilings and defaults for every session on a machine: limits, retention, the dashboard port and who answers approvals.

## Where Tego reads them

Tego reads these layers in order. Each file is optional.

| Order | Layer | Who sets it |
|---|---|---|
| 1 | Built-in defaults | Tego |
| 2 | `/etc/tego/config.yaml` | An administrator, for every user |
| 3 | `~/.tego/config.yaml` of the user who runs Tego | That user |
| 4 | The file named by `$TEGO_CONFIG` | Whoever starts Tego. It adds to the layers above and replaces none of them. It must be an absolute path, and a missing file is an error. |
| 5 | The rules file | For ceilings only (below) |

A key is one of two kinds:

- A **ceiling** (`tier`, `capture`, `limits.*`, `record.max_run_bytes`): each later layer, the rules file included, may lower the value it inherited and never raise it. A rules file that asks for more keeps the inherited value. Built-in ceilings are unbounded.
- A **setting**: the last layer that sets it wins. `denied_resolved_addresses` is the exception: every layer adds to it, and none removes from it.

To see the value in force and the file and line it came from, run `tego rules check <file>`. Its `machine` section lists each value.

## Which files Tego trusts

Tego refuses a layer that another user could change. Each file, and its folder, must be a regular file owned by root or by you, with no group or other write permission. Otherwise `tego run` exits 125 before the agent starts:

```
machine config untrusted: <path> <owner> <mode> [config-untrusted]
```

`/etc/tego/config.yaml` must also be readable by the users who run Tego: mode 0644, owned by root, does that.

## Settings you can change

| Key | Default | Meaning |
|---|---|---|
| `tier` | `auto` | Ceiling. `auto` is the highest level the machine allows. `landlock`, `cgroup` or `bpflsm` pins every session to that level, Basic, Plus or Max ([Protection levels](/docs/tiers/)). `cgroup` and `bpflsm` sessions need root. |
| `limits.cpu`, `cpu_weight`, `memory`, `memory_high`, `pids`, `tokens`, `cost_usd`, `wall`, `stall_after`, `repeats` | unbounded | Ceilings on the same keys in a rules file's `limits:`, in the same units, for example `memory: 32GiB` or `wall: 24h` ([Rules file fields](/docs/rules-reference/)). |
| `ledger_root` | `~/.tego/runs` | The folder that holds session records. |
| `retention` | `30d` | How long `tego gc` keeps an ended session's record. |
| `gc_interval` | `0s` | How often a `tego run` start also removes records older than `retention`. `0s` never does. |
| `stop_grace` | `10s` | How long a stopped session's agent has after SIGTERM before Tego kills it. |
| `record.max_run_bytes` | unbounded | Ceiling. A session whose record reaches this size ends as a limit ([Exit codes](/docs/exit-codes/)). At least `64KiB`. |
| `ask.notify` | `[cli, desktop]` | How a person learns an action waits: `cli` prints the answer commands when the session starts, `desktop` shows a desktop notice (Basic only). `[]` turns both off. |
| `ask.timeout` | `5m` | Read and stored. Each session waits for the `ask.timeout` of its own rules file ([Approvals](/docs/approvals/)). |
| `prices` | `~/.tego/prices.yaml` | The price table that `cost_usd` budgets use ([Budgets](/docs/budgets/)). |
| `registry` | `~/.config/tego` | Where `tego run <name>` finds `agents/<name>.yaml`. `""` turns the registry off. |
| `serve.port` | `8484` | The port the dashboard listens on when started without `--addr`. Every session refuses the agent's connections to this port. |
| `denied_resolved_addresses` | `[]` | Address ranges, such as `10.0.0.0/8`, that no host name in a rules file's `net.allow` may reach. |
| `log.level` | `info` | `debug`, `info` or `warn`, for Tego's own log. |

### Machine-wide only (`/etc/tego/config.yaml`)

Tego ignores these keys in any other layer, with a warning.

| Key | Default | Meaning |
|---|---|---|
| `local_roles` | `off` | `owner_only` makes every approval for sessions started after it come from root, outside every session ([Approvals](/docs/approvals/)). `off` keeps approvals with the user who started the session. |
| `bpf.linger` | `5m` | How long Plus's kernel programs stay loaded after the last session that used them ends. |
| `bpf.ring_budget` | `256MiB` | The memory every live Plus or Max session's event buffers may use together. A session that would pass it is refused, exit 125. |
| `bpf.plane` | `auto` | Which kernel hook mechanism Plus and Max use: `auto`, `lsm` (the kernel's security hooks) or `fmod_ret` (hooks that change a kernel function's return value). |
| `record.ringbuf` | `2MiB` | The size of each Plus or Max session's event buffer. |
| `lsm.list_file` | none | A file holding the kernel's list of security modules, for a container that cannot read the list itself. Tego reads it only when the kernel's own two sources fail, and uses it only for checking held file opens ([Containers](/docs/containers/)). |
| `tomoyo.facts_dir` | none | A read-only copy of the host's `/sys/kernel/security/tomoyo`, for a container on a host that runs TOMOYO ([Containers](/docs/containers/)). |

## Example settings file

```yaml
version: 0
ledger_root: /var/lib/tego/runs
retention: 14d
gc_interval: 1h
limits:
  memory: 8GiB
  wall: 24h
record:
  max_run_bytes: 1GiB
```

## Next steps

- [Rules file fields](/docs/rules-reference/): the `limits:` keys these ceilings cap.
- [Sessions and records](/docs/sessions-and-records/): where records live and how `tego gc` removes them.
- [Approvals](/docs/approvals/): `local_roles` and who may answer a held action.
- [Self-check](/docs/self-check/): `tego machine check` shows a `tier` ceiling in force.
