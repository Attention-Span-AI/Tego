---
title: Self-check
description: "Check what this machine can enforce with tego machine check, and watch Tego refuse four harmless actions on decoy files with tego machine test."
summary: "Two commands that show what this machine can enforce, and prove it."
section: Reference
group: Machine
order: 3
---

Two commands check a machine. `tego machine check` reads the kernel and reports the highest protection level a session started from your shell can get. `tego machine test` starts four short sessions and shows Tego refusing what it should.

Neither needs root or changes anything of yours.

## `tego machine check`

```sh
tego machine check
```

It checks, one line each:

| Check | What it looks at |
|---|---|
| `kernel` | The kernel version, and which newer kernel features this one lacks. |
| `btf` | The kernel's type information, which Plus and Max need to load their programs. |
| `cgroupv2` | Whether your user has its own part of the cgroup v2 tree (a cgroup is how Linux groups a session's processes), and its controllers. |
| `landlock` | Landlock, the kernel feature Basic uses to limit files, and its version (ABI). |
| `seccomp` | Whether Tego can install its seccomp filter (a kernel filter on the agent's system calls), and the `ptrace_scope` value. |
| `lsm` | The kernel's active security modules. Max needs `bpf` among them. |
| `programs` | Whether the kernel programs Plus and Max use load and attach. |
| `fanotify` | The kernel's file-access notifications, which Plus uses. |
| `swap` | Whether a session's memory limit covers swap too. |

Each line starts with `ok`, `FAIL`, `skip` or `off` (a feature only a higher level needs is missing), then the details. A failing line ends with its own `fix:`. After the checks come:

- a table of what each capability does at this machine's level;
- `tier:`, the highest level a session started from this shell gets: `landlock` (Basic), `cgroup` (Plus) or `bpflsm` (Max), where Plus and Max need root;
- `missing for <level>:` lines, one for each higher level, naming what it lacks;
- `fix:`, the one change that unlocks the next level, when there is one;
- whether the dashboard can tell which session a connection comes from.

Last, in a terminal, it prints a verdict and the next command. The output says "tier 1" for Basic:

```
Ready: this shell can enforce at tier 1 (landlock), no root needed.

next: see Tego refuse four harmless actions on decoy files:
  tego machine test
```

Run without `sudo`, it reports what your own sessions get, which is Basic at most. Run with `sudo`, it reports what a session started as root gets, which is where Plus and Max show.

| Flag | What it does |
|---|---|
| `--json` | Prints one JSON object instead of the text. |
| `--require <level>` | Exits 211 unless this machine reaches `landlock`, `cgroup` or `bpflsm`. Use it as a gate in a script or a CI job. `cgroup` and `bpflsm` are reached only with root. |
| `--no-scope` | Checks this shell without trying to open a user scope from it ([Servers and CI runners](/docs/servers-and-ci-runners/#over-ssh)). |

[Exit codes](/docs/exit-codes/#other-commands) lists its exit codes.

## `tego machine test`

```sh
tego machine test
```

```
Tego self-check: 4 actions, 4 refused at tier landlock

  ACTION                                               WITHOUT TEGO  UNDER TEGO  REFUSAL
  read a fake SSH key in a fake home                   succeeded     refused     read-denied: fs.deny_read[<tmp>/work/home/.ssh/]
  write a file outside the project's writable folder   succeeded     refused     write-outside-contract: no entry of the contract allows it
  run a program the contract does not list             succeeded     refused     exec-not-allowed: no entry of the contract allows it
  connect to a local port the contract does not allow  succeeded     refused     net-not-allowed: no entry of the contract allows it

Each action works on this machine without Tego, and Tego refused and recorded every one.
The actions ran on decoys in a temporary folder, removed now, and the four runs' records went there too.
```

It makes a temporary folder in `$TMPDIR` (or `/tmp`) and fills it with decoys. They are a fake home with a fake SSH key and `.env`, a small project whose `out/` folder is the only writable one, a copy of `/bin/true`, and a network listener of its own. Then it runs each action twice:

1. Without Tego. The action must work, or a refusal later would prove nothing.
2. As the agent of `tego run` under a built-in rules file. The action must be refused, and the session's record must hold the refusal.

The REFUSAL column is the reason and rule from that record. "Contract" in that column is the older name for the rules file. `<tmp>` stands for the temporary folder. Tego removes the folder when the test ends, and the four sessions never appear in `tego session list` or the dashboard.

| Flag | What it does |
|---|---|
| `--json` | Prints one JSON object (schema `tego.selftest/v1`). Its `verdict` is `pass`, `fail` or `inconclusive`. |
| `--tier <level>` | Pins each session's level, as `tego run --tier` does: `auto`, `landlock`, `cgroup` or `bpflsm`. `cgroup` and `bpflsm` need root. |

[Exit codes](/docs/exit-codes/#tego-machine-test) lists its exit codes.

The four actions are ones Tego refuses at every level. The test does not show what a level lets through. [Security and limits](/docs/security-and-limits/) covers that.

## Next steps

- [Protection levels](/docs/tiers/): what Basic, Plus and Max enforce.
- [Supported systems](/docs/supported-systems/): what each level needs from the kernel.
- [Troubleshooting](/docs/troubleshooting/): when a check fails.
