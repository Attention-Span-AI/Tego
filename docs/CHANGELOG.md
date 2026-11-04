# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), one section per tag, each ending in the three
lines `docs/VERSIONING.md` requires so a reader can tell what a binary speaks without pulling it: Record `v` /
Contract schema / Kernel minimums. Versions: [Semantic Versioning](https://semver.org/), `0.y.z` until 1.0
(`docs/VERSIONING.md` section 1).

## Unreleased

### Security

- Every enforcing run applies fixed refusals for protected host IPC, Tego control surfaces and other terminals,
  before ordinary contract grants. The run's own runtime, fixed SSH-agent exceptions, inherited terminal and
  policy-checked own PTYs remain usable; an exact container-daemon socket allow warns about escape authority.
  Root tiers add native Unix peer checks and reject `io_uring: true`. Inherited descriptors, new outside FIFOs,
  unlisted server paths and datagram/copied-path cases without a native plane retain documented limits.
- (SEC08) keep unreadable AppArmor namespace depth fail-closed by default; add the explicit
  top-level contract opt-in `fs.apparmor_assume_root_namespace: true` for administrators accepting hidden
  ancestor restrictions. Compile warns and `run_start.best_effort` records the option. The VM matrix
  requires SELinux/Smack live-policy fixtures without skips; per-PR CI does not run those live proofs.

- By default held file opens require matching complete AppArmor labels from a proven root policy namespace, or matching
  SELinux contexts and `fscreate` for potential file creation. Smack completions refuse because another task's process
  rules cannot be queried. Unknown authority facts fail closed, including for approvals and alternates.
- A masked securityfs LSM list can use the unprivileged kernel enumeration syscall. Matching-label
  containers keep working when the required facts remain available; hidden AppArmor namespace depth
  still returns `EACCES` with `held-label-unavailable` by default.

- Held reads retain the identities of protected files and denied-directory descendants, so renames, hard links,
  replacements and move chains cannot turn them into readable aliases. Approvals and alternate files check the
  opened identity too, including write-only approvals. Lost mutation history or an unsupported filesystem refuses
  held reads; new name-rule matches outside the launch snapshot and mount changes made and undone between reads
  remain limits. Ordinary held write opens also recheck live blocks before delivery.
- Ledger and anchor writers reject hard-linked record, lock and anchor files for every user. This does not protect
  records from their owner or add link-count checks to historical readers and garbage collection.
- A stdio MCP relay registers and pins its exact child before exec, closing pending-start theft by a preexisting
  child. Existing `mcp relay *` grants still work through a narrowly authenticated private stage; explicit denies
  and asks still apply. Old relay protocols are refused: rebuild the launcher and shims together. MCP remains a
  preview, with the ptrace/socket-copy and alternate-command limits in [GAPS C50](GAPS.md).
- Boundary adoption prepares and arms its empty destination before moving any process. The decision plane refuses
  CAP_SYS_ADMIN in every user namespace, covering mount changes and mount-namespace installation; missing hook
  proof refuses boundary adoption. Record-only adoption is unchanged. Earlier changes, operations already past the
  capability check, outside processes, inherited descriptors, NET07 and NET08 remain limits.
- Node command rules scan config and dotenv options across the arguments Node actually scans. Expanded option
  inventories require an attested standalone Linux x64 Node 20.19.4 or 22.21.1 executable. Other builds retain the
  previous bounded parser plus these scans, including the documented unknown-build and `NODE_OPTIONS` limits.
- Demo command output masks Claude OAuth tokens and Anthropic API keys while preserving their exact argument
  bytes. Demo resets and developer cleanup require ownership markers and reject protected or unmarked paths,
  including newline-only entries and failed listings. Old unmarked demo state needs manual relocation or a fresh
  path; shell markers guard accidental cleanup, not concurrent hostile path replacement. Source builds use a fresh
  marked BPF toolchain cache and leave the old unmarked cache untouched.
- Release signing runs in a separate job with no checkout, project code or build hooks. It verifies release assets
  and the image digest before signing; publication waits for reproduction, vulnerability scanning and signing.

- A stdio MCP start is bound to the admitted shim's exact child by a pidfd registered before exec. A child forked
  before its parent became the shim can no longer steal the pending start (GAPS C51). Failed registration refuses
  the start; relay protocols v1/v2 are refused, so rebuild launcher and shims together.
- Existing `<tego-path> mcp relay *` grants continue to work. Tego conditionally admits the private stage only
  for the admitted shim's exact fresh-socket child, with a retained pidfd; no broader user grant is needed.
  Direct stage attempts and other tego subcommands receive no permission from it. Explicit denies/asks still apply.
- The MCP relay remains preview functionality (`--preview` exposes its dashboard link). A run with ptrace or
  `pidfd_getfd` authority over the shim/server can still bypass tool decisions and their ledger lines; other command
  spellings need separate exec rules (GAPS C50). The owner's hardening decision remains
  [proposed in ADR 0126](adr/0126-mcp-tool-rules.md#proposed-amendment-2026-11-03-preview-or-security-boundary).

### Fixed

- Protected host-server paths that the invoking user cannot traverse no longer prevent startup; reachable
  objects remain pinned and unexpected identity errors still refuse launch. Compiled built-in entry names
  stay the same when host servers are installed or removed. Record-only adoption remains unrestricted.
- Native Unix peer checks use the correct kernel-memory reader, and protected-name walks keep the original
  verifier instruction budget across kernels.
- Permitted overlay copy-up can use kernel-installed filesystem credentials without granting the agent
  CAP_SYS_ADMIN; task-initiated mount changes and trusted xattr operations, including through an io_uring
  personality, remain refused. Missing kernel
  bind/listen metadata is explicitly disclosed instead of inferred from a copied attempt. Frozen bind lookup
  errors keep supervisor ownership and one observed result with their actual errno.
- Interactive Claude examples use short private session socket paths, check the complete path at launch and
  refuse an overlong path with a fix. PTY peer delivery checks filesystem policy, live blocks and gates without
  changing the supervisor's controlling terminal.
- Developer correctness tests synchronize with observed readiness, lock state and peer admission, and bound Unix
  socket fixture paths. Fast-path timing tests retain their original uninstrumented budgets in
  `scripts/timing-budgets.sh`, with separate instrumented unit/race ceilings; production limits are unchanged.
- Dashboard event windows, indexes and pending asks have bounded retained state, with partial-history labels and
  explicit truncation. Full-ledger receipts report a limit error rather than an incomplete unanswered-ask count.
  Historical reads may rescan disk; these budgets are not a process memory cap.
- Dashboard live regions retry after a failed refresh even if no new event arrives. Watched-run comparisons require
  matching workspace and agent identity, preserving warnings when that identity is absent or different.
- Receipts, dashboard verdicts and learned rules keep successful read/send pairs together; an unrelated refusal no
  longer creates a leak warning. Proximity remains a heuristic. Newly written refusal/mirror pairs are contiguous,
  and created-link and unanswered-ask totals agree across views; older displaced mirrors can remain ambiguous.
- Fresh agent setup generates explicit, portable Claude print-mode and Codex contracts without seeding credentials.
  Codex settings-source notes appear in compile and verbose output, keeping ordinary starts quiet.
- `tego status --agent` selects the newest matching run; `--all` lists every matching retained run. Last-run
  selection skips startup records with no events while still refusing unreadable or corrupt records. Run
  abbreviation verification includes anchored runs whose directories have been deleted.
- Suggested block commands quote paths and option-like program names safely. Exec summaries expose fileless and
  dropped-program facts. Service-mode intentional stops return 143 after escalation while preserving actual ledger
  exit status; OOM/process limits and record errors keep their distinct exit codes.
- Release publication verifies and preserves the tagged changelog text, including recovery when a draft edit fails.

- Tagged releases retain their changelog section in the release body. GoReleaser's changelog pipe stays enabled to
  read `--release-notes`; the publisher checks the draft against the release job's same-run notes artifact immediately
  before publication and verifies the published body and public status. Edit errors also trigger readback and an
  attempt to restore draft status, including when the update applied remotely before the command reported failure.

### Added

- `tego rules` shows the same rules-in-force view as the dashboard, with text and versioned JSON, sources, hits,
  enforcement details and live state. Before a first run, `rules --last` explains how to start. Like the dashboard,
  this command requires a non-root user.
- Inventoried Node builds resolve ordinary option-heavy commands without spending the ambiguity budget on script
  arguments. A bounded executable-digest cache avoids rehashing stable builds. Numeric names such as `node-22` now
  use the Node row. `--stack-trace-limit` is no longer accepted as a command-rule predicate because the inventoried
  versions disagree on its arity; this does not ban the option itself.
- The release workflow publishes multi-platform amd64/arm64 GHCR images containing the reproduced release binaries,
  with keyless signatures, provenance and a recorded index digest. The container base is not claimed reproducible,
  and a signing failure can leave an unsigned registry image while the GitHub release stays a draft.

- Tagged releases publish `ghcr.io/attention-span-ai/tego` for Linux amd64 and arm64 with the exact released
  `tego`/`tego-control` binaries, a keyless cosign signature and build provenance. Release notes include the digest.
  Stable releases update the version, major.minor and latest image tags; prereleases update only their version.
  The install guide documents verification and running the image. Signing runs in a dedicated job with no build
  hooks; build jobs cannot request OIDC tokens. Exported CI tests enforce the permission and publication boundaries.

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
