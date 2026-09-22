# Tego

Tego runs an AI coding agent under rules you write. The Linux kernel and Tego's supervisor, a process outside the
agent, enforce them. It refuses what the contract rules out (files, programs, network hosts), can pause an action until
you answer, and keeps a hash-chained record of each run. What that record holds depends on the tier: by default, tier 1
records programs, writes and connections, and no file reads. The agent is an ordinary process: Tego does not need to know what it is, and it never calls a model
itself.

This repository holds the engine, the `tego` command, the three enforcement tiers, a dashboard for one person on
their own machine, and the kernel programs.

## What it does

- Runs an unmodified agent process under a per-agent contract, a YAML file.
- Enforces the contract from outside the agent's code, so a prompt-injected or mistaken agent cannot talk its way past
  it. At every tier the kernel refuses writes and programs outside the contract. Hosts are decided by Tego's supervisor at
  tier 1 and by the kernel at tiers 2 and 3.
- Writes a hash-chained record of every run. `tego receipt` and `tego events` read it, and the dashboard shows it.
- Ends a run that passes its limits (tokens, cost, time, stall, repeats) with exit code 124.
- Sends nothing on its own behalf: no telemetry, no update check, no crash reports.

## What it does not do

- It does not stop what an allowed program does inside its own memory. If `python` is allowed, Python can do anything
  Python can do.
- It does not stop data leaving through a destination you allowed. Rules match `host:port`, not what the connection is
  used for, so an allowed model endpoint and an allowed `github.com:443` are equally open. Treat every allowed host as a
  way out.
- It is not a sandbox that hides the machine. The agent can read any path that is not in `deny_read`.
- It limits only what the contract names. With no `net:` section every IP destination is reachable, and with no `exec:`
  section every program runs.
- Not every rule is the kernel's at every tier. At tier 1 the supervisor, in user space, decides command rules and
  `deny_write` targets on its copy of the arguments, which is best effort: a racing thread of a hostile agent can change
  what the kernel then acts on. [spec/backend/CAPABILITIES.md](spec/backend/CAPABILITIES.md) lists each rule by tier.
- By default it does not record reads at tier 1. Under `record: summary`, the default, Tego is not told about them: an
  allowed read leaves no line, and a read that `deny_read` refuses fails with `EACCES` and leaves no line either. The read
  is still refused, but `tego run` can print `refused 0` and `tego receipt` can print "Nothing was refused" after it, so a
  clean receipt there says nothing about reads. `record: full` records reads and makes every open slower. Tiers 2 and 3
  record them without it.
- The record is tamper-evident against an agent held by a contract, not against the person who started the run. A
  record-only run (`tego watch` with no `--boundary`, `tego run --observe`) has no Landlock rules, so its agent, which
  runs as you, can rewrite its own record.
- Linux only. On macOS and Windows, run it inside a Linux VM.

The full list, with what to do about each, is in [docs/GAPS.md](docs/GAPS.md). Read it before you rely on Tego.

## Tiers

| Tier | Needs | Gives |
|---|---|---|
| 1, `landlock` | Landlock ABI 2 or newer (Linux 5.19 or later, or RHEL 9's 5.14; tested from 6.1 and on RHEL 9), cgroup v2 with a subtree delegated to your user, no root | Landlock and a seccomp supervisor: file, program and network rules, held requests, a record of exec, write and connect, not of reads |
| 2, `cgroup` | root (`sudo`), Landlock ABI 2 or newer, cgroup v2, BTF | cgroup-attached BPF and fanotify: the kernel records reads too |
| 3, `bpflsm` | root, and `bpf` in the kernel's boot LSM list | Tier 2, with the decision plane running as BPF LSM hooks |

All three tiers are in the binary that `make build` produces. `tego doctor` says which tier your machine gets, and each
run records the tier it had. Details, including the one boot line Ubuntu needs for tier 3, are in
[docs/TIERS.md](docs/TIERS.md).

## Install from source

You need Linux, `git`, `make` and Go 1.27.

```sh
git clone https://github.com/attention-span-ai/tego
cd tego
make build
mkdir -p ~/.local/bin
install -m 0755 bin/tego bin/tego-control ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
```

Keep `tego` and `tego-control` in the same directory: `tego serve` hands off to the `tego-control` beside it and
refuses any other. Add the `export` to your shell's profile if your login does not already put `~/.local/bin` on
`PATH`. There is no tagged release yet, so source is the way to install. [docs/INSTALL.md](docs/INSTALL.md) has the
details.

## Quickstart

Run these in a plain terminal, as yourself. Over SSH, first start a shell in your user's cgroup with
`systemd-run --user --scope bash` ([docs/INSTALL.md](docs/INSTALL.md#check-the-machine)).

```sh
tego version
tego doctor
tego test
mkdir demo && cd demo
tego init --preset no-secrets,repo-only-writes --write ./out
tego compile agent.yaml
tego run agent.yaml
tego receipt --last
```

`tego test` runs four harmless actions against decoy files and shows Tego refusing each one; it needs no root. The
rest writes a small contract, shows its rule table, runs a demo command under it and prints what its record holds.
[docs/QUICKSTART.md](docs/QUICKSTART.md) walks through each step and explains the output.

## Dashboard

`tego serve --open` starts a dashboard on `127.0.0.1` for one person: runs, logs, refusals, held requests you can allow or
deny, each run's rules, and a way to stop a run or block something while it runs. A run started with `sudo` is root's
until it ends, so the dashboard shows it only then; until then use `sudo "$(command -v tego)" status`.
`--preview` also lists the pages for MCP tool rules and model routes. See [docs/DASHBOARD.md](docs/DASHBOARD.md).

## Where to read next

[docs/README.md](docs/README.md) is the map. The user guide is in [docs/user/](docs/user/README.md), real agent
contracts are in [examples/agents/](examples/agents/README.md), and the design is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) says how to build, test and send a patch. Report a vulnerability through the
private route in [SECURITY.md](SECURITY.md), not in a public issue.

## License

[Apache-2.0](LICENSE). The kernel programs under `bpf/` are dual
[GPL-2.0-only / BSD-2-Clause](LICENSES/README.md) (ADR 0012). [Third-party notices](THIRD_PARTY_NOTICES.txt) cover
the dependencies and the dashboard's Lucide icons.

Claude, Codex and other product names are trademarks of their owners; Tego is not affiliated with or endorsed by them.
