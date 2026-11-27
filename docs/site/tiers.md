---
title: Protection levels
description: "Tego enforces your rules at one of three protection levels, Basic, Plus or Max. What each level enforces, what it needs, and how Tego picks one."
summary: "Basic, Plus and Max: what each level enforces and how Tego picks one."
section: Core concepts
order: 3
---

A protection level is how much of your rules the Linux kernel enforces on this machine. Tego has three: Basic, Plus and Max. Basic needs no root. Plus and Max need root through `sudo` and enforce more in the kernel. Tego picks the highest level the machine and your permissions allow, and each session's record names the level it ran at.

## The three levels

Flags, the `tier:` field and `tego machine check` use technical names for the levels:

| Level | Technical name | Root |
|---|---|---|
| Basic | `landlock` | No |
| Plus | `cgroup` | Yes, through `sudo` |
| Max | `bpflsm` | Yes, through `sudo`, plus one boot setting |

Each level is named after the kernel feature it starts from:

- **Landlock** is a Linux feature that locks a process and its children out of files without root.
- **cgroup** (control group) is how Linux groups a session's processes. Plus attaches small kernel programs (BPF programs) to the session's cgroup.
- **BPF LSM** lets those kernel programs run at the kernel's security hooks (LSM, Linux Security Modules), the points where the kernel checks a file open or a program start before it happens. Max uses them, and needs root.

At every level, Tego's supervisor runs beside the agent. It is a separate process outside the agent that checks the agent's system calls through a seccomp filter (a kernel filter on system calls).

## What each level enforces

| | Basic | Plus | Max |
|---|---|---|---|
| Files | Landlock and the supervisor | Basic's checks, plus a kernel file listener (fanotify) | Plus's checks, plus kernel security hooks that know each file by its inode (the kernel's own record of a file, which a rename keeps) |
| Programs | Landlock and the supervisor | Basic's checks, plus the kernel file listener | Plus's checks, plus kernel security hooks |
| Network | The supervisor makes each TCP connection for the agent | BPF programs on the session's cgroup decide in the kernel | Same as Plus |
| File reads in the record | Only with `record: full`, which slows every open | Recorded by BPF | Recorded by BPF |
| Held reads (`fs.ask_read`) | Yes | No: the rules file is refused | No: the rules file is refused |
| Adjustable live mode | No | Yes | Yes |
| Time, memory and process limits | Yes | Yes | Yes |

What Max adds is kernel security hooks for files and programs.

At Basic some checks run outside the kernel; [Security and limits](/docs/security-and-limits/#what-tego-does-not-stop) says what that means.

Held reads are on [Approvals](/docs/approvals/). Adjustable mode is on [Live changes](/docs/live-changes/). Token and cost limits are on [Budgets](/docs/budgets/).

## How Tego picks a level

With no pin, Tego runs the session at the highest level that is available. Without `sudo`, that is Basic. With `sudo`, it is Plus or Max, whichever the machine supports.

To pin a level, use one of these:

- the `--tier` flag on `tego run`, for example Plus (`--tier cgroup`), which needs root
- the `tier:` field in the rules file, for example `tier: bpflsm`
- the `tier` machine setting, which an administrator sets as a ceiling for every session on the machine ([Machine settings](/docs/machine-settings/))

A pinned level the machine cannot give is refused: `tego run` exits with code 125 and the agent never starts. Tego never falls back to a lower level the machine offers. The `tier` machine setting is the exception: a `tier:` pin in the rules file above that ceiling runs at the ceiling. A `--tier` flag above it is refused with exit 125. `--tier auto` and `tier: auto` mean no pin.

To start a session at Plus or Max:

```sh
sudo "$(command -v tego)" run <rules-file>
```

`"$(command -v tego)"` passes the full path of your `tego`, because `sudo` does not search `~/.local/bin`. The launcher runs as root for the whole session. The agent runs as you, with your `HOME`, and the record goes to your own `~/.tego`.

> **Warning:** Granting `sudo` for `tego` is granting root. Read [what runs as root](/docs/security-and-limits/#what-runs-as-root) first.

## Which level your machine gets

```sh
tego machine check
sudo "$(command -v tego)" machine check
```

The first command shows what you get without root, the second what you get with it. Each prints a `tier:` line with the technical name of the level. [Self-check](/docs/self-check/) explains the rest of the output.

By platform:

- **Linux:** all three levels, depending on the kernel and its settings.
- **macOS:** in Tego's Linux VM, Basic with no setup, Plus with `sudo`, and Max after one boot setting.
- **Windows:** in WSL, Basic only.

Plus and Max also need a readable tracefs, the kernel's tracing file system. [Supported systems](/docs/supported-systems/#plus) lists what each level needs and how to turn on Max.

## Next steps

- [Supported systems](/docs/supported-systems/): what each level needs from the kernel.
- [Refusals](/docs/refusals/): what the agent sees when a level refuses an action.
- [Security and limits](/docs/security-and-limits/): what no level stops.
