# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), one section per tag, each ending in the three
lines `docs/VERSIONING.md` requires so a reader can tell what a binary speaks without pulling it: Record `v` /
Contract schema / Kernel minimums. Versions: [Semantic Versioning](https://semver.org/), `0.y.z` until 1.0
(`docs/VERSIONING.md` section 1).

## Unreleased

## v0.1.1 - 2026-11-09

This patch tightens the built-in refusals around an agent and checks the file identities and security labels
used for approvals. Receipts and the dashboard give more reliable results for long runs, `tego rules` brings the
rules view to the terminal, and release automation adds signed container images alongside the binaries. MCP tool
rules remain a preview, with the limits below.

### Security

- Syscall outcome hooks refuse loading or adoption unless tracefs proves an eight-byte return at offset 16.
  Doctor and run tier selection withhold root tiers on unverified layouts and retain the reason.
- Enforcing runs refuse protected host IPC, Tego control surfaces and other terminals before grants. Own
  runtime, fixed SSH-agent exceptions, inherited terminals and policy-checked own PTYs work; exact
  container-daemon socket grants warn of escape authority. Root tiers add native Unix peer checks and reject
  `io_uring: true`. Limits remain for inherited descriptors, new outside FIFOs, unlisted server paths and
  datagram/copied-path cases without native checks.
- Held opens require matching complete AppArmor labels with proven root namespace visibility, or matching
  SELinux contexts and `fscreate` for potential creation. Smack refuses: another task's rules cannot be queried.
  Unknown facts refuse approvals and alternates. An unprivileged syscall discovers LSMs behind masked
  securityfs. Containers need them; hidden AppArmor namespace depth gives `EACCES` / `held-label-unavailable` by
  default. Administrators can waive only unreadable depth with `fs.apparmor_assume_root_namespace: true` in the
  top-level contract, accepting hidden-ancestor risk; compile warns and `run_start.best_effort` records it.
- Held reads track protected identities through renames, hard links, replacements and moves, including
  denied-directory descendants. Approvals (including write-only) and alternates recheck opened identities. Lost
  mutation history or unsupported filesystems refuse held reads; new name matches outside the launch snapshot
  and mount changes undone between reads remain limits. Held writes recheck live blocks.
- Record, lock and anchor writers reject hard links for everyone. Owners can still alter records; historical
  readers and garbage collection gain no link-count checks.
- Stdio MCP starts pin the admitted shim's exact child before exec, refusing preexisting children; failed
  registration refuses. `mcp relay *` grants use an authenticated private stage, honoring denies/asks without
  permitting other children or subcommands. Protocols v1/v2 refuse: rebuild launcher and shims together. MCP
  stays a preview (`tego serve --preview` exposes its dashboard link): ptrace/socket-copy authority can bypass
  decisions and their record; alternate command spellings need separate exec rules ([GAPS C50](GAPS.md)).
  Hardening remains [proposed in ADR
  0126](adr/0126-mcp-tool-rules.md#proposed-amendment-2026-11-03-preview-or-security-boundary).
- Boundary adoption arms its empty destination before moving processes. The agent cannot use `CAP_SYS_ADMIN` in
  any user namespace, covering mount changes and mount-namespace installation; missing hook proof refuses
  adoption. Record-only adoption stays unrestricted. Earlier changes, operations past capability checks, outside
  processes, inherited descriptors/mappings and pre-attachment actions remain outside protection. Adoption
  refuses network contracts (`net:`); it cannot enforce them.
- Node rules scan config and dotenv options wherever Node scans them. Expanded parsing needs exact standalone
  Linux x64 builds 20.19.4 or 22.21.1; others keep bounded parsing plus these scans. Unknown builds may miss
  code-loading options; external `NODE_OPTIONS` preloads remain unread.

### Fixed

- RHEL 9 root-tier runs with `net.listen` can attach their required bind/listen outcome hooks. Bind, listen
  and exec outcomes use the individual syscall event's BTF context; v0.1.0's listener preparation failed on
  the tested RHEL 9 5.14 layout. No required hook or enforced property is dropped.
- Root-tier recording samples shared tracing skips from the programs executing through active links.
  Receipts and views report `bpf-trampoline-miss/shared-build` as shared skipped executions, with incomplete
  coverage, rather than known lost events. Missing, changed or unreadable attachments/counters report uncertainty;
  skips may belong to other runs or ungoverned tasks, and overlapping runs may count the same skip. Preemptible
  kernels can still lose records (GAPS C53).
- Built-in `.env` rename refusals and `tego learn` explain root-tier pip's name-coverage limit (C55) and its
  measured contract/cwd remedy in [OPERATIONS.md](OPERATIONS.md#directory-moves-and-protected-names-c55).
  Write entries alone add no name coverage; pip's copy fallback can exit 0 while recording rename refusals.
- Kernel-matrix guests prepare delegation and authenticated Unix diagnostics/loop modules; doctor-only checks
  accept combined remedies. Automount tests use the same kernel's native result, and conformance releases
  compile-only fixture trees before kernel tests. The 6.1 plane retains its probe reader and kernel minimum.
- Protected host-server paths that the invoking user cannot traverse no longer prevent startup; reachable
  objects remain pinned and unexpected identity errors still refuse launch. Compiled built-in entry names stay
  the same when host servers are installed or removed.
- Native Unix peer checks use the correct kernel-memory reader, and protected-name walks keep the original
  verifier instruction budget across kernels.
- Permitted overlay copy-up can use kernel-installed filesystem credentials without granting the agent
  CAP_SYS_ADMIN; task-initiated mount changes and trusted xattr operations, including through an io_uring
  personality, remain refused. Missing kernel bind/listen metadata is explicitly disclosed instead of inferred
  from a copied attempt. Frozen bind lookup errors keep supervisor ownership and one observed result with their
  actual errno.
- Interactive Claude examples use short private session socket paths, check the complete path at launch and
  refuse an overlong path with a fix. PTY peer delivery checks filesystem policy, live blocks and gates without
  changing the supervisor's controlling terminal.
- Developer correctness tests synchronize with observed readiness, lock state and peer admission, and bound Unix
  socket fixture paths. Fast-path timing tests retain their original uninstrumented budgets in
  `scripts/timing-budgets.sh`, with separate instrumented unit/race ceilings; production limits are unchanged.
  The VM matrix, run by hand before a release, requires live SELinux/Smack policy fixtures without skips;
  per-PR CI omits these proofs.
- Dashboard event windows, indexes and pending asks have bounded retained state, with partial-history labels and
  explicit truncation. Full-ledger receipts report a limit error rather than an incomplete unanswered-ask count.
  Historical reads may rescan disk; these budgets are not a process memory cap.
- Dashboard live regions retry after a failed refresh even if no new event arrives. Watched-run comparisons
  require matching workspace and agent identity, preserving warnings when that identity is absent or different.
- Receipts, dashboard verdicts and learned rules keep successful read/send pairs together; an unrelated refusal
  no longer creates a leak warning. Proximity remains a heuristic. Newly written refusal/mirror pairs are
  contiguous, and created-link and unanswered-ask totals agree across views; older displaced mirrors can remain
  ambiguous.
- Fresh agent setup generates explicit, portable Claude print-mode and Codex contracts without seeding
  credentials. Codex settings-source notes appear in compile and verbose output, keeping ordinary starts quiet.
- Agent selection with `tego status --agent` uses the newest matching run; `--all` lists every matching retained
  run. Last-run selection skips directories with no ledger file while still refusing unreadable or corrupt
  records. Run abbreviation verification includes anchored runs whose directories have been deleted.
- Suggested block commands quote paths and option-like program names safely. Exec summaries expose fileless and
  dropped-program facts. Service-mode intentional stops return 143 after escalation while preserving actual
  ledger exit status; OOM/process limits and record errors keep their distinct exit codes.
- Demo commands mask Claude OAuth tokens and Anthropic API keys in printed environment assignments while
  preserving their exact argument bytes. Demo resets and developer cleanup require ownership markers and reject
  protected or unmarked paths, including newline-only entries and failed listings. Old unmarked demo state needs
  manual relocation or a fresh path; shell markers guard accidental cleanup, not concurrent hostile path
  replacement. Source builds use a fresh marked BPF toolchain cache and leave the old unmarked cache untouched.
- Release publication preserves the tagged changelog section. The publisher checks the draft against the
  same-run notes artifact immediately before publication, then reads back the body and public status even if
  editing fails. After editing, an error, mismatched body or unverified state fails publication and triggers an
  attempt to restore draft status; a failed restore needs manual inspection.
- A contract string that the YAML writer stored as a block starting with a tab or a line break (a multi-line
  `command` entry, for example) is now saved double-quoted in the run's `contract.yaml`, so the saved copy loads
  back as the same contract when `tego drift` reloads it. Such a contract's hash changes; no other contract's bytes
  or hash change.
- Docs: Microsoft's WSL kernel lists `bpf` in its boot LSM list from 6.18.54.1 (WSL 3.0.3), so tier 3 no longer needs a
  boot change there. INSTALL.md also now says PowerShell must be opened as administrator, and covers Lima's menu, the
  read-only Mac home mount and `--mount-none`.
- A YAML anchor or alias used in `gate:`, `ask:` or `docker:` (a gate rule repeated as `*name`, for example) is
  expanded before the contract is saved, so the run's `contract.yaml` loads back for `tego drift`, and two contracts
  whose gates score differently never share a contract hash. Such a contract's hash changes. Contracts generated by
  `tego watch` and `tego adopt` now load for any program path, including one that starts with a space, a tab or a
  line break.
- Release: the signing step stages each checksummed asset from goreleaser's artifact list and the checksum globs, and
  refuses a missing, duplicate or changed file, so a tag's release job no longer stops on a raw binary or an extra
  file that goreleaser leaves outside `dist/`.
- `tego compile` refuses a `net.allow` `unix:` entry that a built-in refusal always refuses, such as the session bus
  or the systemd user manager, as a `contradiction` naming the entry and the rule (such a contract now fails at launch
  with exit 125 instead of running with an entry that never applied), and notes that `host_sockets: true`
  beside a `net:` section has no effect; `tego learn` no longer proposes such a socket, and
  `docs/user/built-in-refusals.md` shows a one-verb helper for an agent that must restart a service.
- The user service template `examples/systemd/tego-agent@.service` sets `Delegate=yes`, so on RHEL 9 the user
  manager activates the delegated controllers along the service's ancestors and a governed service's runs can use
  `limits.cpu`; an interactive run there still lacks cpu (GAPS B15).

### Added

- The `tego rules` command shows the same rules-in-force view as the dashboard, with text and versioned JSON,
  sources, hits, enforcement details and live state. Before a first run, `rules --last` explains how to start.
  Like the dashboard, this command requires a non-root user.
- Inventoried Node builds resolve ordinary option-heavy commands without spending the ambiguity budget on script
  arguments. A bounded executable-digest cache avoids rehashing stable builds. Numeric names such as `node-22`
  now use the Node row. `--stack-trace-limit` is no longer accepted as a command-rule predicate because the
  inventoried versions disagree on its arity; this does not ban the option itself.
- Release automation publishes `ghcr.io/attention-span-ai/tego` for Linux amd64 and arm64 with the exact
  reproduced `tego`/`tego-control` release binaries, keyless cosign signatures, provenance and an index digest
  in the release notes. Stable releases update version, major.minor and latest image tags; prereleases update
  only their version. Signing alone can request OIDC tokens and runs without checkout, project code or build
  hooks, verifying assets and the image digest first. Publication waits for reproduction, vulnerability scanning
  and signing; exported CI tests check these boundaries. The container base is not claimed reproducible; signing
  failure can leave an unsigned registry image while the GitHub release stays a draft. The install guide covers
  verification and use.

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
Syscall outcome hooks require readable tracefs event formats with an eight-byte `ret` at offset 16; unsupported
or unverified layouts withhold root tiers. The kernel version minimum is unchanged.

## v0.1.0 - 2026-11-03

The first release. Tego runs an AI coding agent under a contract you write, a YAML file of rules for files, programs
and network hosts, and enforces it from outside the agent: the Linux kernel and Tego's supervisor refuse what the
contract rules out, can hold an action until you answer, and keep a hash-chained record of every run. Tego runs on
Linux (amd64 and arm64); on macOS and Windows it runs inside a Linux VM. It sends nothing home and never calls a model
itself.

### Install

- Linux: `curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh` installs
  `tego` and `tego-control` into `~/.local/bin`, checks them against the release's checksums, and checks who published
  them when `cosign` or a logged-in `gh` is on `PATH`.
- macOS: `limactl start --name=tego https://github.com/Attention-Span-AI/Tego/releases/latest/download/tego.yaml`
  starts an Ubuntu 24.04 VM with Tego installed (`brew install lima` first).
- Windows: `wsl --install -d Ubuntu-24.04`, then the Linux line inside Ubuntu.
- From source: `make build` (Go 1.27). `docs/INSTALL.md` has every route and what each was tested on.

### Added

Contracts

- `tego init` writes a starter contract, from the built-in presets `no-secrets`, `no-prod` and `repo-only-writes` with
  `--preset`; `tego compile` checks one and prints its rule table, and `--test` asks what each tier would do with an
  action; `tego learn` proposes a contract from what a finished run did. Revision 1 of each preset is frozen from this
  release on.
- Rules for files (`fs`), programs (`exec`), network hosts and ports (`net`), environment variables and limits (tokens,
  cost, time, stalls, repeats, memory, processes). A run that passes a limit ends with exit code 124.

Three enforcement tiers, all in the release binary

- Tier 1 (`landlock`), no root: Landlock and a seccomp supervisor. The kernel refuses writes and programs outside the
  contract; Tego's supervisor decides network hosts.
- Tier 2 (`cgroup`), root: BPF programs attached to the run's cgroup, and fanotify. Hosts are decided in the kernel.
- Tier 3 (`bpflsm`), root, on a machine with `bpf` in the boot LSM list: BPF LSM hooks.
- `tego doctor` says which tier a machine gets and prints a fix for each gap; `tego test` shows four harmless actions
  refused at that tier, with no root and no agent.

Live rules and approvals

- An `ask` rule holds a file open or a connection until you answer with `tego approve` or `tego deny`, or in the
  dashboard. Held file reads (`fs.ask_read`) are tier 1 only; `exec.ask` is reserved and refuses.
- A running run can be paused, resumed, stopped and blocked (`tego pause`, `resume`, `stop`, `block`, `unblock`), and
  `tego rule` turns something a run did into a rule. A run in the Adjustable live mode (tiers 2 and 3) can also be
  loosened while it runs (`docs/user/live-modes.md`).
- MCP tool rules: a relay allows, holds or denies single tools of an MCP server, and `tego mcp` changes that live.

The record

- Every run writes a hash-chained record, anchored in `~/.tego/chain.log`. `tego receipt` summarises a run, `tego events`
  prints it and `tego events <run> --verify` checks its chain, `tego drift` compares what was allowed with what was
  used, and `tego measure` counts steps, tokens, cost and time. What the record holds depends on the tier: by default
  tier 1 records programs, writes and connections, and no file reads (`record: full` records reads).

The dashboard

- `tego serve --open` serves a dashboard on `127.0.0.1:8484` for one person: runs, logs, refusals, held requests to allow
  or deny, each run's rules, and stop, pause and block. It runs as `tego-control`, which refuses to run as root.

The agent watcher

- `tego watch` runs any command as a black box and records what it does. `tego agents` lists the agent processes
  running on the machine and `tego adopt` moves one that is already running into a governed run; both need root.

Supported agents

- `examples/agents/` has contracts for Claude Code (print mode and the full-screen interface), OpenAI Codex (API key
  through Tego's forwarder, or a ChatGPT sign-in), a Python agent on the Claude Agent SDK, one on the Anthropic Python
  SDK, a Python retriever with one MCP server, and an agent of your own left to run unattended. Any other agent is an
  ordinary process: write a contract for it, or start with `tego watch`.

Release

- Static binaries for Linux amd64 and arm64, with the tier-2 and tier-3 BPF objects built in. The checksums file is
  signed with cosign (keyless, by this repository's release workflow at this tag) and every file it lists has a build
  provenance attestation; the binaries are built again from the tag on a fresh runner and must match byte for byte
  before the release is published. `install.sh` and the macOS template `tego.yaml` are release assets too, in the same
  checksums file, and the one-line installs take them from the latest release. `tego_0.1.0_licenses.tar.gz` holds the
  licence texts, and `tego licenses` prints them.

### Security

Fixed since the source was first published on 2026-11-02.

- At tier landlock an agent could open a `deny_write` file such as `.git/config` for writing through a symlink whose
  body goes through its own `/proc/self/task/<tid>` and climbs back out. The supervisor now resolves such a link the
  way the agent's own lookup does, and the open is refused.
- A run with a `net:` section can no longer source-route around its contract: `setsockopt` of `IP_OPTIONS`,
  `IPV6_RTHDR`, `IPV6_2292RTHDR` and `IPV6_2292PKTOPTIONS` fails `EPERM`, and a datagram whose control message routes it
  is refused with a `relay-source-routed` line (GAPS C34).
- The built-in `deny_read` list also refuses the desktop keyrings, `~/.my.cnf`, `~/.mylogin.cnf`, `~/.s3cfg`, `~/.boto`,
  rclone's config, the RubyGems and Composer credentials, `~/.m2/settings-security.xml`, and the doctl, hub, glab,
  flyctl, Supabase and OCI CLI stores.

### Fixed

Since the source was first published on 2026-11-02.

- Set up a new agent takes a long form and keeps a comment on the name line; removing an entry listed twice removes
  both; `tego rule` changes read in words in the dashboard's history and undo the right way.
- `tego gc` and the retention pass prune the rule-change journal, keeping everything a run in the ledger root still
  reads and each rules file's newest 20 standing changes.
- The Block now terminal line fills in what the form holds, quoted, and keeps a selection.
- A run can no longer watch what it may not read: inotify, fanotify and dnotify watches of a `deny_read` target are
  refused.
- Live blocks, gate rules and the model guard read this host the same way, local routes included (AnyIP ranges,
  hand-set broadcast and IPv6 anycast addresses).
- `tego init --preset` makes a preset's folders with no link followed, and works inside a tego run.
- An agent that runs `chmod 000` on tego's own files no longer makes its run fail or refuses the runs after it; tego
  gives the owner back the rights it needs, and `tego gc` deletes nothing by a config layer it cannot read.
- The dashboard reads a run whose launcher died as Lost within a few seconds, re-checks a cached chain verdict, and
  keeps a live host block's addresses fresh.
- tego block notes a program whose file has other names (a multi-call coreutils or busybox) and a bare name on no
  PATH folder; the dashboard's Remove on an ended run is refused as tego unblock is.
- The CLI's record views count a refusal once when its mirror line is not next to it, as the dashboard does.
- tego rule and the dashboard's previews warn when a host a change adds does not resolve.
- tego help marks the commands that need root; `tego-control serve --addr` takes [::1]; error pages keep the live
  chrome; file rows offer Block; `compile --test` says which tiers auto leaves out and why.
- tego run's end line names the tier, and every command that takes a run accepts a unique abbreviation of its id; a
  bare short name is no longer read as a local run directory (use ./name).
- The Rules page lists the machine's limit ceilings, net.http, ingress and gate rules and the tier-1 datagram residual,
  counts what the defaults decided, and counts every name of a program's file, git's helpers and a script's interpreter.
- Logs and the line page say "Watched only" for a watched run's lines.
- The line page streams a blob download instead of holding it in memory.
- The demo kit runs under a pyenv or asdf python3 shim and says when a run did not start; the supply-chain demo's proof
  reads `tego events --json`, and its reset never deletes a folder it did not move.
- tego watch and tego adopt name themselves in the run path's messages.
- Logs: the `path:` query key matches whole names, so `path:/a/b` no longer lists `/a/bc`.
- The dashboard words six refusal reasons it showed as bare codes (MCP tool blocked, Sandbox boundary, and the
  credential and model-route codes).
- Never allow from a Deny on a connection opens that connection's own refusal; Make it permanent is offered only where
  the dashboard can change contracts; the Act panel shortens the run's folder and home only as whole paths.
- The dashboard's rule service keeps its listing of the ledger root while the root is unchanged (a Change rules request
  on 5,000 runs: 1.0 ms instead of 21 ms).
- The receipt, the Receipt tab, tego run's end line and tego watch's footer no longer count writes to /dev/null or the
  terminal as files written, and the tile agrees with the end line; `tego receipt --json` codes each coverage gap.
- Approval cards say what a held delete, mkdir, rename or link changes, in words, with both names whole.
- An adoption's reaper and `tego adopt --release` / `tego stop` no longer recreate files in a removed run directory.
- The dashboard's run timeline and line pages chip an ask Asked and an answer Denied, Allowed, Timed out or Withdrawn,
  as Logs does, instead of "Recorded".
- The Rules page says when a run's rules file loads to other rules than the run ran even when nothing dates the change,
  and no longer calls the file of a run that recorded no contract hash changed.
- Compare paints a green Stopped only for what the run's verdict counts; any other refused connection reads Refused.
- `tego doctor` gives its answer first: a `summary:` line names the tier and what each higher tier needs.
- `examples/systemd` ships a daily retention timer and an opt-in daily restart for always-on agents.
- The dashboard's empty pages give commands that run interactive Claude Code and Codex.
- The Rules pages never show an `env.set` value from a broken file or a file of more than one YAML document.
- A run no longer adopts TLS capture probes left over from before the build's BPF maps were re-created, which lost
  that library's capture with no gap; it places its own, or reports a gap while another run still holds the old ones.
- `tego licenses` and `tego-control licenses` print the licence texts and third-party notices each binary embeds.
- `tego drift` lists every exec of a program held in memory or that ran a file the run wrote, with its verdicts.
- `tego compile` warns when `io_uring: true` meets a `net:` section with no `net.listen` at a root tier, where a ring's
  listen goes unrefused.
- `examples/prices.example.yaml` is a price table to start from (docs/OPERATIONS.md "The price table"), every example's
  header names its setup, and the examples compile on a fresh machine after it.
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
- `tego drift` says what its gaps mean, as `tego status` does, and the dashboard's Rules page says that every run
  can read the machine's network setup (interfaces, addresses, routes and nearby machines).
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

### Known limitations

See `docs/GAPS.md`. The ones most likely to matter on the first day:

- Every destination a contract allows is a way for data to leave (A1), and an allowed interpreter can do anything inside
  its own memory (A2).
- At tier 1, under the default `record: summary`, a read that `deny_read` refuses is still refused but leaves no line,
  so a clean receipt says nothing about reads; `record: full` records them. A record-only run (`tego watch` with no
  `--boundary`, `tego run --observe`) has no Landlock rules, so its agent can rewrite its own record.
- Tier 3 needs `bpf` in the boot LSM list, which Ubuntu and the stock WSL2 kernel do not have by default (B1).
- `tego serve` is for one person on one machine. It listens on loopback and refuses to run as root.
- Piping the installer into `sh` runs it before anything can check it (B11); `docs/INSTALL.md` shows how to check it
  first.
- The macOS template and the Windows script have not been run on those systems yet.

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
