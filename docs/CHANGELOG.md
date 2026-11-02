# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), one section per tag, each ending in the three
lines `docs/VERSIONING.md` requires so a reader can tell what a binary speaks without pulling it: Record `v` /
Contract schema / Kernel minimums. Versions: [Semantic Versioning](https://semver.org/), `0.y.z` until 1.0
(`docs/VERSIONING.md` section 1).

## Unreleased

Changes after the first source release, listed here until the next tag.

### Fixed

- An empty string is not a default. `tego watch --boundary ""` and `tego adopt --boundary ""` ran the command record-only,
  with no rule, and now refuse to start; `tego receipt ""`, `tego init ""`, `tego compile ""` and `tego run ""` are usage
  errors too, so an unset `"$VAR"` never gets a result for something else.
- `tego run`, `tego watch` and `tego adopt` keep going when the reader of their output leaves: `tego run agent.yaml | head -1`
  no longer replaces the agent's exit code with 141 or ends the supervisor under a live agent.
- A run started from a directory reached through a symlink names its real directory in `run_start`, so `tego learn` and
  `tego receipt` read its writes as inside the workspace.
- `tego events` and `tego receipt` print each time in the zone it happened in, and `--until` in an hour a clock change
  repeats is the next time the clock reads it, in every form. `tego learn` measures a run's length on the monotonic clock.
- A limit below what a run's own start takes is caught at compile: `limits.pids` under 6 is refused, and `limits.memory`
  or `memory_high` under 8 MiB, or a machine ceiling that sets one there, gets a warning.
- The agent keeps the soft `RLIMIT_NOFILE` it was started with.
- `record.max_run_bytes` counts a run's stored bodies as well as `events.jsonl`.
- A message the MCP relay refuses unread, or a line past its size bound, is on the record as a refused `mcp` line.
- Dashboard: a proposal made from a run that leaked never allows the address behind the leak's host name; a refused
  connect to a live-blocked host, or one carrying an IPv6 scope id, is no longer folded away as Routine; and a rule made
  from an IPv6 line is one a contract can hold.
- `tego drift` says what its gaps mean, as `tego status` does, and `tego rules` says that every run can read the
  machine's network setup (interfaces, addresses, routes and nearby machines).
- The git exec row knows `git reflog write`, `git hook list` and `git multi-pack-index compact`, which git added after
  2.51.0.
- The container image works for any `TEGO_UID`: its home is 0755, so the entrypoint, which runs as root without
  `CAP_DAC_OVERRIDE`, can reach `~/.tego`.
- The open deputy that serves held reads no longer dies under concurrent requests in a tego built with cgo (a plain
  `go build` with a C compiler): glibc's CPU-count read is refused instead of killing it. The release and `make build`
  binaries are static and were never affected.
- A held open in flight when the open deputy is gone is refused `held-unavailable`; it no longer gets the deputy's socket
  error (`ECONNRESET`, `EPIPE`) as its own errno.
- A run's reaper reads only the unified line of `/proc/<pid>/cgroup`, so on a host that also lists a cgroup v1 hierarchy
  a zombie in a sub-cgroup is no longer charged to `limits.pids`, which could end a healthy run as `reason=pids`.

### Tests

- The suite holds on GitHub's hosted runners: kernel 7.0, which refuses an IPv4 source route to an unprivileged task
  itself (CVE-2026-53249), arm64, git 2.56 and the race detector's pace.

## v0.1.0 - unreleased

The first version. No release has been tagged, so build it from source (`docs/INSTALL.md`). Tiers 2 and 3 are in the
binary that `make build` produces; the limits that remain are in `docs/GAPS.md`.

### Added

Running an agent

- `tego init` writes a starter contract (`agent.yaml`). With `--preset` it writes one from the built-in presets
  (`no-secrets`, `no-prod`, `repo-only-writes`), the folders you may write (`--write`), the hosts you may reach
  (`--allow-host`) and a command (`--command`). `tego init --list` prints the presets.
- `tego compile` validates a contract and prints its rule table. `--test` evaluates a hypothetical action per tier
  without running anything.
- `tego run` runs an unmodified agent process under a contract and ends with a summary. Its exit code is the agent's;
  124 means Tego stopped the run on a limit, 125 means Tego itself failed.
- `tego test` is a one-second self-check with no root: four harmless actions on decoy files, each refused and recorded.
- `tego doctor` tests the kernel (BTF, cgroup v2, Landlock, seccomp, LSM list), prints the tier the machine gets and
  one fix line per gap.

Enforcement

- Three tiers, all in the binary: Landlock plus a seccomp supervisor with no root (kernel minimums below); cgroup-attached
  BPF plus fanotify with root; BPF LSM with root on machines with `bpf` in the boot LSM list. Every run records the tier
  it had.
- Rules for files (`fs`), programs (`exec`), network hosts and ports (`net`), environment variables and limits.
- Held requests: an action can pause until you answer with `tego approve` or `tego deny`, or in the dashboard.
- Limits for tokens, cost, wall-clock time, stalls and repeats end a run with `cgroup.kill` and exit 124.
- Live changes to a running run: `tego block`, `tego unblock`, `tego pause`, `tego resume`, and the Locked and Adjustable
  live modes (`docs/user/live-modes.md`).
- MCP per-tool rules (`tego mcp`) and model routes (`tego route`) for a running run.

Seeing what happened

- A hash-chained record of every run, anchored in `~/.tego/chain.log`. `tego events` prints it and checks the chain;
  `tego receipt` summarises a run (time, files, connections, secrets read, refusals, asks, tokens); `tego drift`
  compares declared against used; `tego measure` counts steps, tokens, cost and time; `tego status` shows a run's state.
- Model traffic is attributed to the step that caused each action where capture can see it (OpenSSL uprobes and a
  loopback forwarder for `models[]`), with a `gap` event where it cannot.
- `tego learn` proposes a contract from what a finished run did, and `tego rule` turns something a run did into a rule.
- `tego serve` starts a dashboard on `127.0.0.1` for one person: runs, logs, refusals, held requests, each run's rules,
  and stop, pause and block buttons. `--preview` also lists the MCP tools and Model routes pages.

Agents already running

- `tego watch` runs any command as a black box and records what it does. `tego agents` lists agent processes and reports
  new ones. `sudo tego adopt` moves a running agent's process tree into a governed run.

Release tooling

- `.goreleaser.yaml`, `scripts/install.sh` and the tag process in `docs/VERSIONING.md` section 7. The first tag also needs
  the steps listed there.
- The installers are in the signed checksums file, so you can check one before you run it (`docs/INSTALL.md`). That does not
  help a script piped into `sh` (`docs/GAPS.md` B11).

### Known limitations

See `docs/GAPS.md`. The ones most likely to matter on the first day:

- Every destination a contract allows is a way for data to leave (A1), and an allowed interpreter can do anything inside
  its own memory (A2).
- Tier 3 needs `bpf` in the boot LSM list, which Ubuntu and the stock WSL2 kernel do not have by default (B1).
- `tego serve` is for one person on one machine. It listens on loopback and refuses to run as root.

### Record `v`
1 (`spec/record/v1`, record minor 29)

### Contract schema
0 (`spec/agent/v0`; the field set may change without notice before v0.2.0, `docs/VERSIONING.md` section 3)

### Kernel minimums
Linux 5.14 with Landlock ABI 2 or newer, which is Linux 5.19 or a backport such as RHEL 9's 5.14; tested from 6.1 and on
RHEL 9 (tier 1: ABI 1 is unsupported, and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
