# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), one section per tag, each ending in the three
lines `docs/VERSIONING.md` requires so a reader can tell what a binary speaks without pulling it: Record `v` /
Contract schema / Kernel minimums. Versions: [Semantic Versioning](https://semver.org/), `0.y.z` until 1.0
(`docs/VERSIONING.md` section 1).

## v0.2.0 - 2026-11-26

This release adds a guided first run (`tego start`), a way to remove Tego (`tego uninstall`), a basic scan for agents
(`tego scan`), a Windows installer, a rebuilt dashboard and a receipt for CI runs. It also closes a set of security
problems found since v0.1.3 and adds two guards where no problem was shown. If you use v0.1.3 or an earlier release,
read Security and Upgrading from v0.1.3 below, then update and restart your runs: a run keeps the rules of the build
that started it.

### Security

Each entry below describes code that is in v0.1.3. Earlier releases were not checked one by one: treat them as
affected too. Two entries, the new namespaces and the approval-socket peer, are guards where no run is shown to have
been affected. Where an entry names a virtual-machine run, it says what that run showed. Where it says unit-tested,
no virtual-machine run has shown it. An entry that says neither makes no claim about a virtual-machine run.

- The program that holds your secrets could be read by other programs of your user. `tego run`, `watch`, `adopt`,
  `start` and `setup` held your environment, your saved logins and the keys they unseal in a process that another
  program of the same user, an agent included, could read through `/proc/<pid>/environ`, `/proc/<pid>/mem`, `ptrace`
  or `pidfd_getfd`. These commands now make themselves non-dumpable before they read an argument, and a process that
  cannot do so starts nothing and unseals nothing (`[undumpable]`). What changes for you: a debugger of your own user
  can no longer attach to a `tego run`, and `tego scan` lists a live run's launcher among the programs it cannot read.
  Root can still read these processes.
- The dashboard's sign-in token and keys could be read by an agent. `tego-control serve` holds them in memory. An agent
  of a run with no Landlock domain (`tego watch` with no `--boundary`, or `--observe`), on a host where Yama
  `ptrace_scope` is 0, could attach to the dashboard. The dashboard now makes itself non-dumpable before it does
  anything else and does not start when it cannot. It still answers asks, and an agent that makes itself non-dumpable
  is still refused for being inside its run.
- A denied file could stay readable, and a protected file writable, through a second name at tier landlock. v0.1.3's
  notice called this a stated alias limit. With your home or project bound somewhere else (a container volume, a bind
  mount, a btrfs top-level volume, WSLg's `/mnt/wslg/distro`), a protected file (`.git/hooks`, `.git/config`, a
  `deny_write` entry) could be written through the other name, and a `.env` or a file a `deny_read` pattern matches
  that appeared during a run that held its reads was not refused under every name. Every deny rule now follows the file under every name
  the mount table gives it, and a write entry's other names count as the same grant. A contract Tego cannot keep this
  way is refused at compile, naming the file and the other name. `tego block` covers the other names of a blocked path.
  Separate file system instances that show the same data, and mounts made after the run starts, remain limits. A run
  that reads direct (the default when nothing denied lies inside a writable folder at its start) refuses a file that
  appears later under no name. The WSL path was proved in a Windows guest, and the bind-mount, btrfs and bound-project
  cases in Linux guests. The other name of a `.env` that appears during a run that holds its reads is covered by unit
  tests, not yet by a guest run.
- A process that connected to a run's approval socket was identified by the cgroup of one thread. That is not a sound
  identity for a peer whose first thread has exited; on the kernels we tested such a peer was already refused by a
  later read, so no kernel is shown where it passed. The peer is now identified by the cgroup of every thread and
  refused when its first thread has exited. Proven in a guest with a real process built that way and with an adopted
  process.
- "Cannot tell whether this shell is inside a run" was treated as outside. In a cgroup namespace that is not the
  machine's first one (WSL, some containers), a command that only a process outside every run may use (approving a
  request, `tego setup`, changing a run's rules) went ahead when Tego could not tell. These commands now proceed only on a
  proven "outside"; "inside a run" and "cannot tell" both refuse, and the refusal says which. Where Tego cannot prove
  "outside" it refuses, and `tego doctor` prints a `run membership` line saying what it found. On ordinary Linux
  nothing changes. This is unit-tested; the WSL cases are in the install guide.
- A live MCP switch or model route written into a Locked run's folder was put in force. On a Locked run (the default),
  a switch looser than the contract's decision, or a model route other than direct, that something other than
  `tego mcp`, `tego route` or the dashboard wrote there is now ignored: the contract decides, and the record has a line
  that says who asked and why it did not take effect. A JSON-RPC batch is decided member by member, so one refused call
  no longer fails the whole batch.
- A live `path`, `read` or `write` block did not stop what the kernel decision plane decides, at tiers cgroup and
  bpflsm. It was reported as in force, but the supervisor never sees the write opens, creates, deletes, renames,
  truncates, attribute changes and reads the plane decides. The block is now put in force in the kernel too. Where the
  launcher cannot make the plane's mark, `tego block --list` and the dashboard say the block is partly in force and
  name what it does not cover. A descriptor opened for writing before the block keeps writing, as at every tier.
- A ring's listen was not refused. Under a `net:` section with no `net.listen`, the `io_uring` listen operation
  (Linux 6.11 and later) on a TCP, MPTCP or SCTP socket passed at tiers cgroup and bpflsm. The decision plane now
  refuses it as it refuses `listen(2)`.
- A route in a table that a policy rule leads to was not counted as this host's. Net blocks, `net to` rules, the
  `models[]` guard and tier 2 could misjudge a destination reached by such a route. The policy rules are now read
  before the routes.
- At tiers cgroup and bpflsm a read the kernel refused could be recorded as `observed`, and under held reads no line
  was written. This concerned a name made beside a `deny_read` target's ancestor after the run started. The line is
  now the one tier landlock writes (`refused`, `read-denied`). A run whose ruleset froze directories without a
  snapshot does not start.
- Uprobe capture could expose a kernel fault, at either root tier. Releases v0.1.x could select uprobe capture through an
  omitted `capture`, `capture: auto` or `capture: uprobe`. On a kernel with the BPF private-stack feature (upstream
  kernels before 6.13 lack it), a JIT that supports it, and a preemption mode that lets concurrent tasks interleave in
  one probe on one CPU, one agent can suffice to trigger the fault. Fedora's measured lazy default was exposed;
  Ubuntu 6.17's measured voluntary default was not. Symptoms include missing or corrupt model exchanges, a budgeted run
  ending `error` (exit 125), or a kernel fault that kills a task and leaves later `tego doctor` calls or probe removal
  hung. A host fault can also affect runs that use another mechanism. Uprobe capture now makes a live tail call into an
  empty array to avoid the collision, and the loader requires that call in the instructions read back from the kernel.
  If the loaded call cannot be confirmed, uprobe capture is unavailable: `auto` keeps the forwarder available, and
  an explicit `capture: uprobe` with recording enabled is refused with the reason, which `tego doctor` reports. Where
  host hardening (`net.core.bpf_jit_harden=2` with `kernel.kptr_restrict=2`, as measured on Fedora 7.0.14) hides the
  instructions even from root, uprobe capture is unavailable and Tego does not bypass the setting: use
  `capture: forwarder` with a `models:` endpoint, or relax the setting only if the host owner accepts the tradeoff.
  A live-call stress of 25,200 exchanges ran with no kernel fault or capture loss. Reruns on RHEL 9 and Fedora 7.2 and
  arm64 acceptance are not done.
- A message could print the value of an environment entry. See the first entry of Fixed.
- A timed live block was dropped early when the wall clock was stepped forward by more than a day. Its deadline is now
  kept against the boot clock.
- Rules files on a file system that anything outside Linux can edit are refused. `tego run`, `tego rules edit`,
  `tego start` and the general policy layers now refuse a rules file, or a file it extends, on WSL's Windows drive
  (`/mnt/c`), a 9p or virtiofs share, FAT, exFAT, NTFS or an SMB share, because any Windows program could change it.
  A FUSE file system Tego cannot look up is refused too.
- The filter every run's processes carry already refused a new mount or user namespace; it now refuses a new cgroup
  namespace and a new process-id namespace as well. For a root-level run with `setuid: true` this is a second guard:
  its decision plane already refuses `CAP_SYS_ADMIN` to the agent. Proven in a guest by the record of such a run.
- An agent could take away the owner's rights on run directories with `chmod`. `tego run` (at its start) and
  `tego gc` (without `--dry-run`) give the owner back the rights on the run directories of your live, orphaned and
  earlier runs. A group or other bit is never touched, and another user's directory is left alone.

### Added

First run and everyday commands:

- `tego start` takes a first-time user through four steps: the agent (Claude Code, Codex, a small demonstration agent
  that needs no account, or another program), its login, a project (a test project with a harmlessly poisoned dependency, or your own) and its rules. It shows an
  agent's own install command and where it comes from before it asks to run it. As root it does not run an agent's
  installer: it shows the line to run. It asks before it uses a saved login ("Use your saved Claude Code login?"), and
  logging in again replaces it. Read-only review keeps the project's content read-only: the agent can write only its
  own state folder under `.tego/`, and a project in which that folder is a link is refused.
- A first run needs no account. `tego start` looks at what is on the machine before it asks which agent to supervise:
  for Claude Code and Codex it notes whether the program is installed and whether a login Tego can pass to it is set in
  your shell or saved by `tego start`; it starts nothing and contacts nothing to find out. An agent that is installed
  and signed in comes first. When there is none, the demonstration agent comes first, with a line that says why. It is
  a short script of Tego's own that tries one write its rules allow (in a folder named `demo-out`) and one they refuse,
  in the test project, with no login, no network and no secrets: the guide asks nothing more about it, saves it as
  `tego-demo` with rules that let it write in one folder, runs it once, and ends with the commands that show the run. The login question has a way back to the
  first question for a person who has no account for the agent they chose. Proved on a fresh Ubuntu 24.04 guest (45
  of 45 checks).
- The guide keeps one reader on the terminal from its first question to its last. Ctrl-C at a question ends it, and
  while an agent's installer or browser sign-in runs, Ctrl-C ends only that step and the guide asks the question again.
  Leaving the guide, by Ctrl-C at a question, a closing terminal or a signal, ends every program it started (the
  installer and the dashboard it was starting included), puts the terminal back as it was and says `Stopped` instead
  of `Ready`. A terminal with `TERM=dumb` gets numbered questions that end the same way. The Next
  steps list a `PATH` line when the agent was installed to `~/.local/bin` and your shell does not search it.
- `tego run` uses the login that `tego start` saved (`~/.config/tego/agent.env`) for each variable that is not already
  set in its environment, so the first session works in the terminal the guide ran in. An exported variable wins. A
  saved file that is not your own private file is ignored, with one line that says why.
- Commands now have a git-style shape over the existing ones: `tego rules create|edit|check|learn`,
  `tego session list|show|stop|pause|resume`, `tego machine check|test` and `tego dashboard`. The older names still
  work. `tego help` lists the common commands and `tego help -a` every one. `tego --version` and `tego -V` print the
  same banner as `tego version`.
- Sessions have names (`tego-sample-dzfa`) that every command taking a run accepts. `tego run` in a terminal prints a
  start line with the session name, the rules file and the dashboard page, and an end line with the number of actions
  blocked.
- `tego setup` in a terminal opens the setup guide; `--json` and `-v` keep the checklist. `tego doctor` and
  `tego setup` accept `--no-scope` to check the current shell without rehearsing entry into a user scope.
- `tego uninstall` removes Tego on Linux and macOS (Windows already had a way). It lists what it will remove and asks
  once (`--yes` for scripts): the `tego-dashboard` unit and the clean-up timer, the installed `tego` and the
  `tego-control` beside it, the line `tego start` added to `~/.bashrc` and the installer's `PATH` line (only that
  exact line, with a backup beside the file), and the dashboard's own files. Your records (`~/.tego`) and contracts
  (`~/.config/tego`) stay unless you answer yes to a second question, and your `tego-agent@` services unless you answer
  yes to a third. Both have their own flags (`--delete-records`, `--stop-agents`), so `--yes` never deletes proof or
  stops an agent. A system-wide install is never touched: the command prints the exact `sudo` lines.
- One dashboard per configuration. `tego dashboard` and `tego start` reuse a running dashboard only after it proves
  that it holds its sign-in link and serves the same ledger and machine configuration. Its log and a saved agent
  login are private files (mode 0600) from the moment they exist.

Finding agents and contracts:

- `tego scan` looks for your running agents, installed candidates and settings metadata and saves a private snapshot,
  with its evidence, its coverage and a JSON form. `tego scan --check` is a no-save check for CI. It reads the
  current folder's `package.json` and `requirements.txt`, and lists configured MCP servers from fixed Claude, Codex and
  Gemini settings and configured systemd user services and timers. `tego scan --advanced` adds explicit discovery
  across the visible users, fixed user and system service and timer paths, cron sources and container ids from cgroup
  names. It drops secret values and says which sources it could not read. Programs of your own whose files it cannot
  read are reported with their count and pids, and make the check exit 3. Tego cannot tell whether these are agents; any
  program can make itself unreadable. With `--allow-unreadable-programs`, exit 0 does NOT mean no agent runs outside
  Tego; exit 3 has the same uncertainty. See `docs/user/scan.md`.
- The dashboard's Agents page lists each recorded run and each program a saved scan saw. Each row opens its own
  detail: where it was recorded or seen, first and last seen, the record check and the next step, and each stage with
  what is and is not known. A stage shows as reached only for a recorded run, never from a scan. See
  `docs/user/agents.md`.
- `tego contracts` finds known contracts, checks today's files offline and lists the newest recorded runs of each,
  without running an agent. See `docs/user/contracts.md`.
- The setup guide's "Find your agents" step ticks from a fresh scan.

Rules, approvals and the record:

- A live block can name a command's words. Removing an entry such as `git push` from `exec.allow`, or adding it to `exec.deny`,
  on a running run now offers "Also apply now" with a block that refuses what that text in `exec.deny` would, decided by the
  same matcher the contract's command rules use: `git push` and `git -C . push origin` are refused, `git status` and
  another program's `push` still run. `tego block <run> exec "git push"` and the dashboard's Block now take the same
  words, and `tego unblock` lifts it. For a removed `exec.allow` entry the page offers it only when no other `exec.allow`
  entry of that program may allow part of it, and not for a command written with a path; it is also held back where the
  new rules allow every command of the program (the run's own command, an MCP server or a script's interpreter is that
  program, or a path or folder entry grants it and no entry with words of it is left), since the block would refuse more
  than they do, and the page says why it offers none; an added `exec.deny` entry always has it. A script's interpreter
  (a `#!` line) is looked up on the dashboard's own `PATH`, which can only make the page hold a block back that it need
  not. Proved in guests at tiers landlock, bpflsm (lsm), cgroup (lsm) and cgroup (fmod_ret), for command words, a path
  grant and a folder grant. A run started by a Tego that cannot read it is told so (`tego
  block` exits 1, `[launcher-too-old]`), and no block on the whole program is placed in its stead. The command is read
  from the copy of the argument list Tego's supervisor makes, like `exec.allow` words: a thread of the agent that rewrites
  its arguments after that check can still run it. A live block for a pattern such as `**/.env` is still not offered;
  the change is saved for the next run.
- `tego rules history <agent | file> [--json]` and `tego rules undo <agent | file> [<id>] [--yes]` are the dashboard's
  change history and its Undo, from a terminal. An undo that only narrows needs no confirmation. One that lets the next
  run do more asks for `undo` to be typed at a terminal; with no terminal it needs `--yes`. History and undo list a rules
  file once a run on this machine has run it.
- A saved `tego rules edit` goes through the same writer as the dashboard's Change rules. It keeps the old text as
  `<file>.bak` and adds an entry to the history, listed as a free edit of the whole text, so `tego rules undo` gives the old
  text back (a free edit asks for the word `undo`, or `--yes`). The output names the entry, the `.bak` file and the undo
  command. A file the writer refuses (one that is not yours alone, one every user can write, one under Tego's own
  folders), or a machine with no ledger root yet, is saved as before, and the output says it is not in the change
  history and `tego rules undo` cannot give the old text back.
- `tego rules <session>` shows the same rules-in-force view as the dashboard, as text or versioned JSON, with sources,
  hit counts and live state.
- A lift or a grant of an Adjustable run's fence entry can carry a note: `tego lift ... --note "text"`, and one optional
  text input on the dashboard's lift confirm. The note is at most 200 bytes of printable text, signed with the lift, and
  shown but never acted on. A run started by v0.1.3 refuses the note in words.
- `tego events <run> --cells` prints each event as one line of four tab-separated cells (seq, verdict, rule and
  detail), exactly as the table writes them, for a script. With `--json`, `--verify` or `--follow` it is a usage error.
- The receipt has one published schema, `spec/receipt/receipt-v1.schema.json`. Each coverage gap carries a `level`:
  `partial` (some of the field is recorded, so a count is a floor or an estimate) or `none` (the record is silent on the
  field). A gap that may have lost actions is worded the same way in `tego receipt`, `tego status` and the dashboard.
- The receipt and the dashboard separate UDP attempts that sent from those that only connected: a datagram's `net`
  line carries `op: send`, and the receipt counts `datagram_sends`.
- A launch's `run_start` records the kernel limits its scope holds as `applied_limits` (`cpu_max`, `cpu_weight`,
  `pids_max`, and new `memory_max` and `memory_high`), read back after they were written. A boundary adoption records
  the three it writes. An MCP answer or event-stream message the relay drops for its size, and a model-route overlay
  the forwarder cannot read, are gap lines in the record, not only a log line.
- A run that passes its ledger size limit (`record.max_run_bytes`) says by how much: the lines already queued are all
  written, and the record ends with one gap line (`why=ledger-ceiling-overshoot`) with the bytes past the limit.
- Model steps appear on the run timeline and in Logs, with no new record field. The timeline groups consecutive rows of
  one model step under a header such as "After model request N, matched by time (likely)".
- `limits: {tokens: 1000000, window: 24h}` (or `cost_usd`) makes a budget a total over the last 24 hours across every run
  of the agent, so an agent that a service restarts after each limit or crash no longer gets a fresh budget each time.
  The window is 1 minute to 30 days. The agent is the one `tego run --agent NAME` names, or the contract file's path
  (the same name in two project folders is two agents). Before the run starts, Tego reads the agent's earlier runs from
  its record, checks each against `chain.log`, and refuses to start (exit 125, `[budget-window]`, naming the run and the
  fix) when a run of this agent does not verify, when one of its runs is still live, when `retention` is shorter than
  the window, when the contract has no name, in a record-only run (`--observe`), where the agent could reach its own
  record, or when the agent's records inside the window hold more than 512 MiB. Another agent's damaged record never
  blocks a start, and a mode an agent takes from its own lock file in the ledger root (`chmod 000`) is restored when the
  next run starts, as for its run directories. A held agent cannot lower its own count: at tiers landlock, cgroup and
  bpflsm, appends to its own record and to the chain log are refused. A lock file that cannot be opened refuses the
  start and names the `chmod` that fixes it. A run folder that another host made (a ledger root shared between machines)
  is left out of the count without a line, and a folder of another account that the launcher cannot read is left out
  and the record says so (a `gap` line, `window-unattributed`). A run that ended with no `chain.log` line is counted as its record holds it, and the run says so in a
  `gap` line. `run_start` records the window, and `spec/record/v1/README.md` says how to recompute the total from the
  records. Run a windowed agent under `record: summary` (the default): reading costs about 50 microseconds a line.
  The held-agent rules above were proved in guests: all four variants of the test on Fedora's 7.0 kernel and the three
  root variants on kernel 6.17.

Settings and platforms:

- Held file opens work in a container under Docker's defaults when the image's entrypoint hands in the list of security
  modules. Inside such a container Tego could not read which security modules the kernel runs: the default seccomp
  profile answers `lsm_list_modules(2)` with "not implemented", Debian 12's kernel has no such call, and the container's
  own `/sys` has no securityfs, so every held file open was refused. A new machine setting, `lsm.list_file` (read from
  `/etc/tego/config.yaml` only), names a file Tego reads the list from when neither kernel answer can be read: the host's
  `/sys/kernel/security/lsm` bound read-only into the container, or the file the image's `tego-entrypoint` writes as
  root, before it drops its privileges, to `/run/tego-lsm/lsm-list`. The list has a directory of its own, so a root `tego` in the same image keeps `/run/tego` at
  root's mode 0700. Tego believes the file only while root alone can change
  it and only for this boot: root's, not writable by anyone else, in directories only root can write, no link in its path,
  not on FUSE or a network filesystem, written for this boot (a file left from an earlier boot or copied from another
  machine is refused), and read for a task that is not root and holds no capability in its permitted set that could rewrite it. Each check
  is repeated at every open, and a file that fails one is refused in words that say which; held opens then stay
  refused as before. The list decides held opens only, never which tier a machine offers. It is not the only fact a held open
  reads: on a host that also runs TOMOYO (Debian's kernels do) or AppArmor, the host's TOMOYO files must be bound read-only
  and named in `tomoyo.facts_dir`, and the contract must carry `fs.apparmor_assume_root_namespace: true`, as the container
  guide says. Where the entrypoint cannot read
  the list either, it says why; the fix is the settings of `examples/container/compose.yaml` (`SYS_ADMIN` and
  `apparmor=unconfined`), a host kernel 6.8 or later with a seccomp profile that allows `lsm_list_modules`, or a
  contract that holds no opens.
- A machine with `gc_interval` set gets the retention pass without a `tego run` start: `tego start` and
  `tego dashboard`, when they start the dashboard, also make a daily user timer, `tego-gc`. A timer that is already
  active, including your own copy of `examples/systemd/tego-gc.timer`, is left alone.
- The machine setting `tomoyo.facts_dir` in `/etc/tego/config.yaml` (the administrator's file only) names a read-only
  bind of the host's `/sys/kernel/security/tomoyo` for hosts where Docker's default profile hides the kernel's own
  path. Tego accepts it only on securityfs, on a read-only mount whose root is `/tomoyo`. `tego doctor` names the path
  it read.
- `local_roles: owner_only`, a system-only setting, restricts a qualified root-launched non-root run to once answers
  from root outside every governed run. Same-user terminal and dashboard answers are refused. Stop and restart every
  run started before v0.1.3 before you enable it. See `docs/user/local-approvals.md`.
- A Windows installer: `install.ps1` installs a checksummed native `tego.exe`, which runs Tego in its own `tego` WSL 2
  distribution. `tego dashboard` on Windows opens the dashboard in your browser (PowerShell 5.1, PowerShell 7 and cmd), through a small relay on `[::1]`
  that admits only your own Windows account's programs. `tego dashboard --stop` ends it. WSL's mirrored networking is
  not supported for the browser dashboard. `tego start` and `tego dashboard --stop` tell you to keep a `tego` command
  or a Linux shell open while an agent works, because Windows can stop Tego's Linux when nothing is attached to it and
  that ends any run still going. The Windows installer is unsigned and not fully qualified; see
  `docs/INSTALL.md` for what was tested.
- The Mac installer checks the VM template and the VM's installer against the selected release before it uses them,
  installs that same version in the VM, opens the dashboard only after a tunnel that belongs to you is confirmed, and
  adds `tego` to fish's `PATH`. Pinning a version on a Mac (`TEGO_VERSION`) needs this release or a later one.
- Enforcing starts print a `[startup-wait]` note after about one second while kernel checks and program preparation are
  pending. Fast starts print none.

CI and verification:

- The built-in `tego/ci` preset records refused read opens at tier landlock by default, denies named CI token
  variables and blocks ordinary `.github/` writes. The CI receipt workflow runs an AI agent in CI with separate run and
  comparison jobs, keeps the agent's exit status and refusal policy, and can be signed through a second reusable
  workflow behind explicit consent to a permanent public log. Receipt binding 2 adds machine-readable teardown status,
  and a local verifier checks a receipt against its record. See `docs/user/ci-receipt.md` and
  `docs/user/ci-verification.md`.
- A contract may name one submitted-refund business-rule bundle (`business_rules`). Tego validates the declaration, but a
  run that uses it is refused with exit 125, because activation is not available yet. See `docs/user/business-rules.md`.
- A run keeps its receipt. When `tego run` or `tego watch` ends, the run's folder gets `receipt.json`: the bound
  receipt, exactly what `tego receipt <run> --json` prints, mode 0600, written once and never over a file or link that
  is already there (the run's end says so in one warning and leaves it). It is not kept for a run whose record could not
  be completed, one that was interrupted, or a build with uncommitted changes or no version stamp. A failure to write it
  is one warning and never changes the exit code. `tego receipt <run> --verify` then also compares that file with the
  record after the chain check. It says whether the copy matches, or, as exit 1, that the record verified and only the
  kept copy differs: an edited figure, a copy that names another tego as its maker than the one that ran the run, any
  copy in a run recorded before revision 41, whose build kept none (v0.1.3 and earlier), a file that is no receipt, or a link or pipe at
  the name. After an upgrade the figures of a copy of the run's own build
  cannot be compared by another build, so it says so and exits 0 when the chain verified. A copy in a later release's
  form exits 125 and says only the copy is unchecked. The CI action reads the receipt from the record, never this file,
  so a `receipt.json` planted in the folder does not fail it. The copy is a convenience, not evidence. Proved in a guest: an upgrade from the published v0.1.3, and
  forged, planted, linked, edited and sudo cases (81 checks).
- A machine baseline (`baseline:` in the machine config) is read, compiled and recorded with its hashes. Enforcing
  launches with a nonempty baseline are refused until every mechanism has its proof. See `docs/user/baseline.md`.

The dashboard:

- The dashboard has a new look in the website's brand, local assets only. Orange means a request waiting for a person.
  Refusals, broken records and warnings for protected reads use red; allowed own-login reads and ordinary allowed
  actions stay neutral. At phone widths five destinations sit at the bottom. List rows show who, state and age; exact
  paths, hashes and identifiers stay in details. The shared request band has one sentence, two equal answers and an
  exact-request Details link, and every request link selects its run and request. A missing selection offers no other
  request's controls. Navigation, Filter pages and decision forms work without scripts.
- Displayed numbers use complete aggregates where available. Incomplete windows, omitted runs, malformed lines and capped
  approval history say at least, explain why and link complete records. A record file that cannot be read says could
  not read, with its reason, instead of showing prefix counts. Runs retains Filter and scoped counts at desktop widths.
  A verified record never implies safety.
- A new contract can be made with Simple Keep and Drop decisions or a Full YAML draft editor, including a blank
  starting point. A save uses the exact bytes that were reviewed. Wider rule families, and changed families Tego cannot
  order, need an explicit review. A review expires 30 minutes after it was made.
- An optional guide walks from the stored machine check to a verified enforcing run, with the real product pages. Hide
  it for good, and show it again from the page.
- Logs: a time range set as "the last hour" is pinned to the times it means when it is set, with a Move to now link;
  the Host filter and facet find destinations that were only ever refused; an IPv6 address on two links keeps its zone.
  A query that cannot be read in full lists no lines and says why. The MCP tools and Model routes pages follow the
  ledger in place.
- A rule change shows the direction the compiled comparison found, not the file text's: a pure refusal reads
  "narrows" and needs no confirmation. Undo lifts only the live blocks it can show that change made.

### Changed

- A config layer that is present but unreadable, unparsable, or has the wrong owner or mode now stops commands that
  decide what an agent may do, including launch, compile and rule-check commands. Commands that observe or stop keep
  working, and report an UNKNOWN baseline and the cause. The system layer needs a root-owned file without group or
  other write, readable by governed users (normally 0644). While the configuration is unknown, `tego gc` deletes nothing
  and exits 125.
- Compilation applies baseline refusals once, keeps the contract hash, and adds `tego rules check --effective`.
  Contradictory compiled grants, including home and relative spellings, protected sockets and launch environment
  entries, refuse compilation.
- The Linux installer's last line is `tego start` when the installed `tego` has it. The README's quickstart is four steps
  (install, set up, run, see what happened) and a table of everyday commands.
- `tego run` in a terminal keeps its full summary for accepted risks, failed checks, coverage gaps, incomplete or
  unverified records, record-off runs and abnormal endings, and shows a short success line only when none applies.
  Piped or redirected stderr and `-v` keep the previous output, including the older command names.
- Next-step and `fix` fields in JSON output name the new commands (`tego machine check`, `tego rules check`,
  `tego session show`, `tego rules learn`). A consumer that compares those strings must accept the new names; the old
  commands still work.
- `tego session list` reports an unreadable ledger and exits with an error instead of saying there are no sessions.
- A run that was refused a write to `/dev/null` because no `fs.write` entry covers it (a first rules file such as
  `fs.write: [./]`, then a shell's `> /dev/null`) gets one line under `tego run`'s summary: `/dev/null: refused, no
  fs.write entry covers it (N times); it holds no file: add /dev/null to fs.write so `> /dev/null` works`. A refusal made
  by an entry of the contract, such as a `deny_write`, gets no such line. Since a contract with an `fs:` section may write
  the standard data devices (the entry below), the line appears only where that grant did not apply: under a contract with
  no `fs:` section, or where the host's file at the name is not the device.
- Every contract with an `fs:` section may write `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random` and `/dev/urandom`
  without naming them, at every tier and with no preset. A rules file with no entry for `/dev/null` used to refuse a shell's `> /dev/null`
  and `2>/dev/null`, the first thing a beginner's script does. The grant is to the device itself, found by its major and
  minor numbers (1:3, 1:5, 1:7, 1:8, 1:9): another file at the same name, a link to another file, a node made with
  `mknod` somewhere else, or a regular file mounted at the name gets none (another one of the five devices mounted there is that device, and its own grant holds under every name). It is the right to write, truncate and
  use ioctl on those five files and nothing on a directory, so nothing can be created, removed or renamed in `/dev`.
  Nothing else under `/dev` is granted: `/dev/tty`, `/dev/ptmx`, the pseudo-terminals and `/dev/shm` still need an entry
  of your own. An entry of your own that names a device or a place over it (`fs.deny_write: [/dev/null]`, `fs.deny_read`,
  `fs.ask`, `fs.watch`) decides it instead, and the refusal names your entry. A record line for an open of one of these
  devices now says `allow` and the rule `builtin.standard_devices` where it said `refused` and `unmatched`, and the Rules
  in Force page lists the grant under Always on. Proved in a guest at tiers landlock, cgroup and bpflsm, where nodes that
  only look like the five devices were refused.
- `tego ask` with no run names a run it leaves out. A run that takes approvals but whose ask socket is gone (it closes
  as the run shuts down), or whose start record cannot be read, was passed over without a word, so a list that left it
  out read as the whole. A note on standard error now names it, or says the run ended while the list was made.
  Standard output, `--json` and the exit code are unchanged, and a run whose contract has no ask rule is still not
  mentioned.
- The dashboard reads big ledgers with less repeated work, and gives the same answers. The first text search in Logs
  builds each run's search text on several cores into a buffer sized first (23 MB allocated for 6 MB of text over 68,000
  lines, where it allocated 42 MB). Logs keeps the facet counts and groupings of a run with that run's version, and the
  program index behind the Process column, `prog:` and the Program facet in each run's own read state. Viewers who open
  the same heavy tab of a run together (Receipt, Least privilege, Unused) share one computation. The Rules page takes a
  live run's program folders from lines already decoded (3.3 ms where it took 18.3 ms, for a run of 55,000 lines), and
  reads the rules change journal through a memo that decodes only the lines added since its last read and checks the
  bytes it serves (about 5 ms where a 20,000-line journal took 122 ms). A run's model listeners share one search of the
  cgroup tree.
- `tego help` says what `tego dashboard` does on each system: it prints the link on Linux and opens the browser on a Mac.
- `tego receipt --check` returns `cannot-check` with exit 125 for a missing or unreadable record, instead of a mismatch
  with exit 1, unless a separate check failed.
- Record validation strict-decodes a present `run_start.contract_source` at every record minor, including older
  ledgers: null, case variants of its keys, wrong types, repeated members and unpaired surrogates inside that object
  are refused. A valid older source without learn history is still accepted.
- Every run writes record revision 41 from its first line, so a live block can come at any time after `run_start`. See
  Upgrading from v0.1.3.
- A pause that failed after the run was paused is read by one rule: `tego status`, `tego session list`, `tego stop` and
  the dashboard now all say the run is paused. `tego status`, the dashboard, the receipt and `tego ask` pair an ask
  with its answer by one rule: the first ask of an id opens the question.
- `stall_after` no longer counts Tego's own latency: while the forwarder holds a model request on its way out (its
  approval, route and credential decisions, its connect and TLS handshake), the run counts as held, as during an ask
  or a pause. A model that answers and then goes silent still stalls the run.
- The reason channel gives each session its own refusals and prints a note at least once. The Claude Code hook reports
  pending refusals at session start and states the whole run's scope in every note. The words say printed, not
  received: Tego cannot see whether the harness passed the note to the model.
- The Lima VM template (`examples/lima/tego.yaml`) shares no Mac folder with the VM. It used to mount the Mac home
  read-only and `/tmp/lima` writable. `docs/INSTALL.md` says how to share one folder on purpose and what an agent can
  then read. A VM made from the older template keeps its mounts until you edit it.
- `tego adopt --release` of an agent that was alone in a transient scope (started with `systemd-run --scope`, or
  launched from a desktop as an app scope) now moves it to a cgroup of its own, `tego-released-<run id>`, under the
  nearest ancestor that lets one be made. It used to leave the agent in the adoption's scope with its limits lifted.
- Rules in force and rule-hit counts follow what ran: an `exec.allow` entry with command words (`git status`) counts the
  allowed lines that name it, not every exec of its program.
- A person's own live command against a run launched with sudo says why it cannot. `tego lift`, `grant`, `restore`,
  `block`, the `tego mcp` switches and `tego route` need the run's folder, which is root's until the run ends. They now
  say the run was launched as root and to repeat the command as root (exit 1, `[root-run]`), instead of
  `permission denied [io]`. The dashboard says why it cannot show or change such a run live.
- The dashboard's Logs, Agents and Rules pages, the contract builder and the rule editor use plain words for what a
  change does, say which rule families a change moves and in which direction, and no longer offer Allow or Ask for a
  refused socket that a built-in refusal always refuses.

### Fixed

- Overview: a waiting request whose sentence does not fit on one line beside its answers now takes the banner's
  full row, with the answers on the row below; a short request stays beside its answers as before. A long sentence
  no longer wraps to a third line at 1280 px with a wider monospace font, or to four or five lines at 768 px.
- The Rules page costs 40 to 60 ms of CPU for each refresh of a run of 55,000 lines, where it cost 400 to 550 ms. A
  refresh made two requests to a helper process, a new process for each, and each read the run's whole record again, so
  the dashboard's own copy of the run was never used. The page now takes the run's counts from that copy, or reads the
  record once, and sends them with its requests. `tego rules` on the command line has no such copy: it reads the record
  once and costs about 200 to 280 ms for 55,000 lines, of which about 150 ms is the scan itself (see Known limits).
  What the page shows is unchanged.
- `tego start` and `tego setup` end with their own exit status when a second signal arrives after the guide has put
  the terminal back. An interrupt and a terminate sent together, or a hang-up as the terminal window closes, could end
  the process with the signal instead of the guide's `Stopped` line and exit 1. The guide now keeps handling INT, TERM
  and HUP until the process ends. This is proved by unit tests, which failed 41 of 54 cases before the change and
  passed all 54 after it, not by a run in a guest.
- On kernels older than 6.2 (Landlock ABI below 3, such as Amazon Linux 2023's 6.1 and Debian 12), a `truncate` that the
  first-tier filter refuses, and an `O_TRUNC` open through a read-only access mode, now leave a `refused` line in the
  record (rule `landlock-no-truncate`). The filter answered `EPERM` itself and wrote nothing. The agent still gets `EPERM`,
  for the same calls, and nothing is truncated. Proved in guests on Amazon Linux 2023 with kernels 6.1 and 6.12, on both
  boots of each.
- A program start that failed with permission denied, whose record of what decided it was lost when the kernel's ring
  buffer overflowed, now says so. Its line carries `decision_lost`, the gaps of the run that lost records its decision may
  be among (the run's, not the attempt's: after one loss, every later start that fails with permission denied for any
  cause, such as a `noexec` mount or a missing execute bit, carries it too), `tego events` and the dashboard show it as a failure with a lost decision, and the receipt counts it in a
  figure of its own (`execs_decision_lost`) instead of saying nothing was refused. It is still not recorded as a
  refusal: the record cannot say whether Tego or another security module refused it. The CI action's summary says it too (for example, "`3`
  commands failed with permission denied; the record of what decided them was lost, so they are not counted as
  refusals"). A run that lost no record is unchanged, and v0.1.3 reads and verifies the line. Proved in a guest on
  Fedora's 7.0 kernel with real record loss (one round lost 1,011 records).
- A stall limit in v0.1.2 and v0.1.3 could stop a run that was still making progress if the supervisor was delayed
  between reading activity and checking the time. The watcher now reads the time first. Runs with no activity still
  reach their stall limit.
- On kernels that list TOMOYO as active with no policy loaded, including stock Debian 12 and 13, v0.1.3 refused every
  held file open (`held-label-unavailable`), so approvals on file reads, held reads and the dashboard's demo did not
  work there. They now complete while TOMOYO is unused. A TOMOYO policy that enforces, or one Tego cannot read, still
  refuses. At the root tiers the launcher reads TOMOYO's profile and admits a held open only when no mode is
  `enforcing`. Tier landlock, whose launcher cannot read the profile, keeps the refusal, and the message now says why.
  `tego doctor` says which proof admitted.
- The doctor's `key_permission` probe no longer fails the lsm mode when the Go scheduler moves its goroutine to another
  thread. Before, a failing probe could report a hook as refused when it was not, and the machine could then run a
  weaker decision plane until the next boot. The failing values were never logged, so the cause is inferred from a loop
  that failed 35 of 30,000 times and 0 of 30,000 with the fix. The probe's key steps now stay on one thread.
- A failure while the doctor prepares a probe row's fixture (its key, socket, helper process or file) is a fault, never
  the hook's answer. Before, a refusal made while preparing the key could read as the hook's own refusal, so the hook was
  never exercised and the row could pass. The row now fails with the step and the cause, the mode is not used by the run
  and nothing is cached. A hardened host's refusal of doctor's own calls gets its own fix text.
- A root run's start-up check stops probing the decision plane's second mode once the first has passed every hook.
  Where `bpf` is in the kernel's security-module list, a cold start probed both of the plane's modes, and a mode's probe
  spends most of its time waiting for the kernel to remove the mode's links. A run that takes the first mode no longer
  probes the second. What a run takes is unchanged: a mode is taken only when every one of its hooks counted, a hook that
  did not pass is checked again on its own before it is reported, and a failed first mode, `bpf.plane: fmod_ret`,
  `tego doctor` and `tego machine check` probe both modes as before. Measured in one test guest (kernel 6.17, four
  virtual CPUs, a busy host, 12 cold launches of each build in alternation, and a control run that changed nothing):
  on a boot with `bpf` in the security-module list the median cold start fell from 22.2 to 17.5 seconds at tier
  cgroup and from 21.7 to 17.9 seconds at tier bpflsm (the quartiles of the two bpflsm sets overlapped by 0.07
  second, so that pair is the weaker evidence). On a boot without `bpf` in the list nothing changed (16.4 and 16.5
  seconds), as designed. A cold start at the root tiers is still slow; see Known limits.
- A mode of the decision plane that fails a row of its probe is probed once more. Two probes that fail the same way are
  recorded and cached as before. Two answers that differ are a fault: the run does not use that mode, nothing is cached
  so the next run probes again, and `tego doctor --json` shows both probes under `plane.modes[].probes`. One false
  answer no longer costs the machine the stronger plane until the next boot. A mode that answers differently every time
  is probed twice on every run. A load or attach error, a failed known answer and a mode that passed are not probed again.
  The unit tests hold this with a stand-in prober, and in a guest on a real kernel a test build forced one probe row to
  fail once and every time and checked each outcome. A probe of one mode took 3.5 to 4 seconds in earlier 6.17 test
  guests, so a mode that fails the same way twice adds about that once per boot.
- A second `tego approve` or `deny` of one request, answered as the run ends, is told the truth. It was told
  `connection reset by peer [io]` (exit 125) or, for a run whose contract has an ask rule, `takes no approvals: its
  contract has no ask rule`, which was false. It now says what the record proves: another answer is recorded, or yours
  was recorded on line N, or the run has ended.
- The receipt lists a run's refusals in the order the calls were received, not the order the lines reached the ledger.
- `run_start.applied_limits` is the limit that holds. A run placed under a cgroup with a lower `memory.max`,
  `memory.high`, `pids.max` or `cpu.max` than the launcher wrote is held to the lowest ceiling up to the cgroup2 mount,
  and the record now says that ceiling. A member whose ancestors cannot all be read is left out, and the log names the
  file.
- `net.assurance: kernel` no longer breaks the C library's interface lists (`if_nameindex`, `getifaddrs`, Node's
  `os.networkInterfaces()`) at tiers cgroup and bpflsm, including for a run that holds its opens (`fs.reads: held`).
- `tego scan --check` no longer answers "none observed" when it cannot see every process. Inside a nested PID namespace
  (`unshare --pid --fork --mount-proc`, a container) it answers unknown (exit 125), and a process it cannot attribute to
  one uid counts as uncertainty, not absence.
- `tego receipt` no longer prints the reader's home as `~` for a run recorded by another user or on another machine. It
  folds `~` only under the home the run recorded and otherwise prints every path whole.
- `tego dashboard` and `tego start` reuse a running dashboard. They used to restart it on every call, which signed out
  open tabs.
- The dashboard's live refresh no longer takes away what a person is using: an open "More choices" no longer closes, and
  a click on "Allow for this run" or "Deny for this run" no longer lands on the wrong block when a late note or another
  line arrives. A run with a waiting request is no longer left out at random when the dashboard reads more runs than it
  shows. The ledger reader no longer serves old lines for a file rewritten within one tick of a coarse kernel clock.
- A very busy machine no longer reads as "a disconnected or stuck mount", and a draft compile that did not finish no
  longer says "the new contract does not compile". The checker has its own time to start, and a check that runs out of
  time says `cannot tell` and that nothing was written.
- A background job-group interrupt (`kill -INT %1`) no longer reads as two interrupts for a run started in a user scope
  with piped input, which ended the run at once.
- A run started with sudo prunes the rule-change journal again when a directory above the ledger root may be searched
  but not listed by the invoking user (mode 0711).
- A run ending with reason `signal` or `stopped`, after `tego stop` or SIGINT, SIGTERM or SIGHUP and then killed by Tego
  because `stop_grace` ran out, records the signal that started the stop in `run_end.signal` with `escalated: true`. It
  recorded 9, the kill's own signal. Runs recorded before this release keep 9.
- In a `--observe` run, a send whose address has the family `AF_UNSPEC` is let through, as before, but its line now
  carries the rule `net.unspec-send` and the receipt lists it as observed.
- `tego compile` refuses a `net.ask` entry for a `unix:` socket that a built-in refusal always refuses, as it already
  refused the same entry under `net.allow`.
- `tego learn` over one recording gives the same warnings and counts every time.
- `tego start` accepts executable absolute program paths. Relative program paths ask for a program name or full path.
- The container guide quotes the refusal `tego run` prints on Docker's default settings (`no enforcement tier available on
  this machine [tier-unavailable] ...`, exit 125), and the install guide's container section ends with the check of the
  record: `tego events <run> --verify` from a fresh container on the same two volumes.
- The Linux installer's last line names `tego` by its full path while the install folder is not on the `PATH` of the
  shell the installer ran in. The Windows installer's closing hint works in PowerShell and in cmd. A cold
  `tego start` on Windows that does not confirm Linux's user scope in time says to type the same command again.
- Mac installer messages explain Lima and Homebrew and give the retry command. The installer restores saved terminal
  settings on failures and interrupts. The VM template has only digest-pinned images for Apple silicon and Intel.
  `tego shell` reports usage when given extra arguments. A dashboard tunnel or browser failure after the guide prints a
  retry command and still opens the project shell.
- A message never prints the value of an entry of the agent's environment (the contract's `env` entries, harness entries, credentials, another process's environment), whatever its length: it names the variable, or the entry's position when the entry has no name to tell from its value.
- A value that failed validation is not echoed either: the message names the variable, says what is wrong and how to print it. A folder or file Tego resolved from a location variable (the settings file `TEGO_CONFIG` names, the runtime folder) and a validated run id are printed where the message is about them.
- `tego rules edit` says why the editor did not finish (not found, permission denied, its exit status, the signal that ended it) and no longer blames `EDITOR` for the `vi` it tries when no editor is set.
- The rule table names a `PATH` inherited from the caller's environment instead of printing it; the JSON form carries the value. `tego agents` reports an observed `TEGO_RUN_ID` only when it is a run id.
- Executable paths that hold a space are one program on the dashboard: the Block action, the comparison and the agent recognition read the recorded path and arguments.
- Executable refusal groups use the program name, including recorded executable paths containing spaces.
- Restored live fences keep their refused hosts outside the dashboard's Routine fold; its explanation names the live-block and restored-fence exceptions.
- Mixed watched and enforced Rule facets identify watched lines explicitly.
- Built-in socket contradiction advice names the runtime directory that matched the socket.
- Learn withholds suspicious sockets with a conditional built-in warning when the recording lacks enforcing context, and explains how to check on the agent's machine.
- Unverified single-file memory backing emits the same unknown-backing warning as other unsupported backing.
- Record-only notices and learn advice describe the rules in force and the limits of recording.
- Older product descriptions use rules terminology and include all AI agents.
- `tego stop` of a run that is still starting says so. A run holds its lock before it writes the first line that names
  its agent, and the first start at the root tiers can take seconds to prepare. A stop in that window printed `run has no
  agent id yet [io]` and `still running after 3s (and 3s after cgroup.kill)`, although nothing had failed and no kill had
  been written. It now says the stop is requested and the run is still starting, and the stop stays queued and takes
  effect as soon as the launcher has started the run. It exits 0, as before; a run that has started is stopped as
  before. Checked in guests, in that window, on Fedora and Ubuntu.
- `tego rules undo` run from inside a run, or from a process that cannot be shown to be outside every run, answers with
  the governed refusal (`[governed]`, exit 1) when it cannot list the rules file. A run's own rules can hide the ledger
  root, and the command used to say "no run here has run a rules file yet" (exit 2) before it reached that check. It now
  says why the file could not be listed and that Tego cannot show the undo only narrows, and writes nothing. From a
  process outside every run the usage error is unchanged. Checked in a guest from inside a real Landlock run.
- A desktop's large runtime folders no longer use up the compile step's inventory of named pipes (FIFOs). The inventory
  of the host's runtime and desktop folders counted every entry against one budget of 4,096, and `/run/user/<uid>/gnupg`
  holds a folder for every GnuPG home ever used (4,043 on one machine), so the next real folder (systemd, pulse) was
  refused whole. Files (4,096 entries it reads) and folders (16,384 entries it lists) are now bounded apart. A folder
  past either bound is still refused whole and every named pipe the walk reaches is still refused, so a run is refused
  nothing less than before.
- The demo kit lets a name lookup through avahi (mDNS) work. Its contracts named `/var/run/avahi-daemon/socket`, where the
  library on Ubuntu 25.10 connects to `/run/avahi-daemon/socket`, and a `net.allow` entry for a unix socket admits the
  name as the program spells it. The kit now lists both spellings, each when it exists. A contract of your own still
  needs the spelling its program uses. Checked in guests.
- The words for a security-module list that cannot be read are true for the cause. Under Docker's default settings Tego
  cannot read the kernel's list of active security modules: the default seccomp profile refuses `lsm_list_modules(2)`, the
  file `/sys/kernel/security/lsm` cannot be read either, and Debian 12's kernel 6.1 has no such call. Every held file
  open is refused then, as before. The launch note, the supervisor's log line and `tego doctor` now say what each way
  answered and offer only an option that exists (allow the call in the outer seccomp profile on kernel 6.8 or later, or
  make the file readable; before kernel 6.8 only the file), and doctor says that held opens are refused until the list
  can be read. The old note told a Debian 12 container to permit a call its kernel lacks. No open that was refused is
  allowed. Checked in guests on Debian 12 and Debian 13 with Docker.
- The decision plane's size check follows the kernel it runs on. The root test that holds each plane program to a
  budget of verified instructions failed on Fedora 44's kernel 6.19.10 (100,417 and 59,387 against 95,817 and 57,527),
  because the kernel counts far more verified instructions for the plane's loops from 6.19.4. The programs loaded and attached, the kernel's own
  limit is 1,000,000, and no decision changed. The budget for kernels 6.19.4 to 6.19.y is now the measured count plus
  10 %. The check passed in guests on seven kernels: the mainline builds 6.18, 6.19.3, 6.19.4, 6.19.10 and 6.19.14, and
  Fedora's 7.0 and 7.2. Fedora 44's own 6.19.10 kernel was measured before the change, not after it.
- The decision plane's size check no longer lets its largest program grow unseen. The listener check (`socket_listen`)
  has its own budget of verified instructions, and it was one flat 64,000 for every kernel. Kernels before 7.0 verify it
  in at most 18,892; Linux 7.0 and later count it as about 44,000 with the program unchanged, so a 6.x kernel could take
  three times its count without the test noticing. The budget is now each family's measured count plus 10 % (20,782
  before 7.0, 48,426 from 7.0), and a program whose count the kernel does not give is a failure of the test, not a skip
  on a kernel that reports counts. The same kernels also count the plane's other programs 2 to 5 times higher; they
  stay inside their budgets. No decision changed.
- Root tests now run the rarer paths of live blocks on a real kernel, each with the plane's own counter or the kernel's
  own rows as its control: a block's row whose inode no longer carries its identity refuses, a walk that cannot reach
  the root fails closed, a block that has not begun refuses nothing until its instant and then refuses again, and two
  names of one key refuse alike. They are in the root suites and run on each kernel row there. No decision changed.
- On a phone, the dashboard's week chart of refused actions is drawn by day. 168 hourly bars are under 2 px each at 390
  px and cannot be tapped. At 600 px and narrower the week is up to eight bars, one for each calendar day (the first and
  last may be part days), each a link to that day's refused lines in Logs with a 44 px label and its count. The days add
  up the hourly bars, and from 601 px up the hourly chart is unchanged. The action buttons of a request keep their labels
  whole at 320 px.
- The Several changes at once form on Change rules sends its preview as a form post instead of putting its edits in the
  address. Sixteen entries of a few KB passed the server's 16 KiB header limit, and the browser showed a bare 431 page. A
  preview writes nothing, so a peer inside a run still sees it, without Save. A Save refused because the file moved plans
  the same edits again in place when they are too long to carry back in an address. The single-entry forms are unchanged.
- The dashboard's answer line says what is true when a run's answer socket is gone. It said "the run is not running"
  for a missing socket, which is not known. A run whose launcher is alive but whose socket is absent is now told that
  the socket is gone, the answer was not delivered and the request may still be waiting. A socket with no listener says
  so. Only a run with no live launcher is told it is not running, as `tego ask` already said.
- When an MCP client sends a batch over standard input and one of its calls needs your approval, the calls the rules
  allow now reach the server first. An approval that came back at once could reach the server before them.
- Internal file-check helpers always give their worker slots back to the pool they took them from. A slot returned after
  the pool had been replaced could leave a later check waiting for good.

### Removed

- maze is no longer built or released. The release has 13 files instead of 22; the last release with maze is v0.1.3.
- The component notes under `docs/p0` are no longer part of this repository. The repository's checks require the
  seven public specifications under `spec/` instead; the few checks that could only read those notes are skipped
  by name in the skip lists under `test/`.

### Known limits

What this release does not do, or has not proved, in plain words.

- A cold start of a run at the root tiers (cgroup and bpflsm) can take 9 to 15 seconds in earlier test guests, and 16
  to 18 seconds in a four-CPU guest on a busy host (medians of 12 cold launches, measured for this release). Tego
  prints a `[startup-wait]` note after about one second. In that guest, where `bpf` is in the security-module list
  this release saved about 4 to 5 seconds of it, and elsewhere it changed nothing. Tier landlock runs no BPF probe.
- `tego rules` on the command line has a floor near 150 ms for a run of 55,000 lines, because it scans the whole record
  each time. The dashboard's Rules page does not pay it: it reuses the dashboard's own copy of the run.
- On a computer whose own disk is very busy or nearly full, a dashboard save or check that waits more than five seconds
  for that disk can be refused with "this location does not answer (a disconnected or stuck mount?)" although the
  location is healthy. The dashboard is meant to say "the disk is busy" there, and on this release it cannot tell the
  two apart. Reload the contract and its History before trying again, since a submitted save may already have reached
  the file.
- A root-tier run's launcher uses memory you should plan for. It peaks near 70 MB (57 to 73 MB resident in our
  measurements), holds about 14 MB of its own memory at rest, and shares about 28 MB of memory with the kernel for
  each run. In a test guest, 32 root-tier runs at once used about 1.05 GB of process memory and 0.9 GB of shared memory; they
  passed in a guest of 2,560 MB with under 100 MB to spare, so plan about 3 GB for 32 concurrent runs. This release does
  not lower these figures.
- A file that `tego rules edit` saves is in the change history, and `tego rules undo` can undo it, unless the writer
  that keeps the history refuses the file (one that is not yours alone, one every user can write, one under Tego's own
  folders) or the machine has no ledger root yet. Such a file is saved, and the output says it cannot be undone.
- A run started with sudo can be changed live only as root: your own `lift`, `grant`, `block`, `mcp` and `route` say
  "repeat with sudo", and the dashboard cannot show or change such a run.
- Inside Docker's default settings, and on Debian 12, Tego cannot read the kernel's security-module list itself, so held
  file opens are refused there unless the list is handed in: by the image's entrypoint (started as root with the
  settings of `examples/container/compose.yaml`) or by a read-only bind of the host's list named in `lsm.list_file`. A
  container whose entrypoint cannot read the list and has no bind keeps refusing. The launch note and `tego doctor` say
  which way failed and what can change.
- Under heavy record loss, a refused program start can appear in the record as `observed`, `failed: Permission denied`,
  not as `refused`, because the line that names the refusal was lost. The line now says so: it names the gaps of the run
  that lost records its decision may be among (`decision_lost`), and the receipt counts it in a figure of its own,
  neither as a refusal nor as a program that ran. The record cannot say whether Tego or another security module refused
  that start. The line names the run's stated losses and does not narrow them to the time of that attempt, so after
  one loss every later start that fails with permission denied carries it, whatever the cause. Two other shapes
  carry no such field: a start whose attempt could not be matched with its metadata, and a sample of the decision that the
  recorder could not decode.
- On kernels older than 6.2 (Landlock ABI below 3), a `truncate` of a file under a live block is refused with `EPERM`, not
  the `EACCES` the decision plane gives. The file is not truncated either way, and the record has a `refused` line for
  it under the rule `landlock-no-truncate`, not under the live block's rule. The same refusal covers a truncate the
  rules allow, because the first-tier filter cannot read the path safely. At tier landlock, a `ftruncate` of a
  descriptor that was opened for writing before a live block began is neither refused nor recorded.
- At tiers cgroup and bpflsm, a live block that was unblocked for a while (`tego unblock --for` or `--until`) has two
  limits. With a read block in force and a write block lifted for a while on the same file, the kernel keeps refusing
  writes through the window, because the kernel's row for a file has one start instant. In a time namespace where the
  launcher cannot map the boot clock, an unblock for a while has no effect at these tiers, while the record and the
  dashboard say the block is lifted. In both cases nothing is let through that the block refuses. A plain unblock is not
  affected, and neither is tier landlock.
- Some paths of the plane's live blocks have no run on a real kernel: a run that gives out all 16,383 block ids (the
  class refused whole that ends in is the one the full block map shows on a real kernel; the count itself is a unit
  test), two names whose keys collide over the whole 63-bit hash (the kernel's answer to a key another row holds is
  shown by changing a row's identity in the map instead), and arm64, which has no run at all.
- Inside a container or a private cgroup namespace, the cgroup limits above the container cannot be read, so
  `applied_limits` leaves them out and the log says why. Root-run limits cannot tell btrfs subvolumes apart.
- `tego ask` on a run whose socket is gone exits 1 with `[not-found]`.
- The reason channel (the Claude Code hook) is tested without a real Claude Code session.
- The CI receipt's signing was not tried with real GitHub permission delegation. The Mac uninstall was tested against
  stand-ins for Lima and SSH, not on a real Mac or in a real Lima VM. The Windows launcher's request to keep a command
  open is checked by a unit test, and has not been seen on a Windows console on this release's build. The Windows
  walk-through used no real keyboard or mouse, no signed executable, no real HTTPS release, no Windows 10 and no ARM64.
  Windows is unsigned and not fully qualified; the Mac was walked through by hand on Apple silicon only.
- Root-only local approval (`local_roles: owner_only`) was qualified in one Ubuntu 25.10 guest.
- The update from v0.1.3 was tried with release files built from this release's code and installed from a local folder,
  not with the published v0.2.0 files. What the notes say about v0.1.3 reading this release's records comes from
  running v0.1.3's ledger and record code, not its command line.
- A baseline in the machine config is read, compiled and recorded, but an enforcing launch with a nonempty baseline is
  refused. A contract that names a business-rule bundle is validated and then refused at run start.
- `docs/user/container.md` and the install guide's container section describe a Docker flow that was proved on Debian 13
  at tier landlock only. The words for an unreadable security-module list were also checked on Debian 12.
- Three faults were seen once in test guests and not explained: an exec rule's pin missing on Amazon Linux 2023,
  `tego doctor` killed by SIGKILL on Fedora, and a startup stall under SELinux with an isolated cgroup.
- A budget over a window (`limits.window`) cannot count spend that no record holds: what a launcher killed with its
  agent never wrote, responses the record dropped, runs a person deleted, and a wall clock set forward past the window.
  Its count is read from files of the same account, so it relies on the run being held (landlock or above), which keeps
  the agent from writing its own earlier records. A window is refused in a record-only run. An observe-only run of another agent on the same account can hold the
  agent's window lock or change its mode; that only makes later starts of the agent refuse, and it never lowers the
  count. A restart into a full window ends at its first model response, so a service with `Restart=on-failure` stops
  after its start limit until `systemctl --user reset-failed`.
- When Ctrl-C reaches both the `tego run` command and its launcher, the same Ctrl-C can in rare orderings be counted as
  two (seen about once in 30 runs on one busy CPU, not on an idle multi-core machine); the run then ends as it would after
  a second Ctrl-C. The test that holds this is skipped until it is fixed (public issue 81).
- A budget (`limits:`) stops a run by ending it. Calls the agent makes in the instant between the limit being recorded and
  the run ending are still answered and recorded.
- Tego's own test suite has a few load-sensitive tests that can fail on a very busy machine.

### Upgrading from v0.1.3

- Update by running the install line again. A run keeps the rules and the record revision of the build that started it,
  so stop and restart the runs you want under this release's fixes, and stop and start the dashboard the same way.
  Before you turn on `local_roles: owner_only`, stop every run that v0.1.3 or an earlier release started.
- Your records. A ledger says its own revision in `run_start.record_minor`. v0.1.3 writes revision 30. This release
  writes revision 41 on every launch and every adoption, whether or not a live block comes later. Revision 41 holds
  everything that revisions 31, 39 and 40 add. Revisions 32 to 35 are declared and validated but no release writes
  them, 36 and 38 are reserved and refused, and this build also reads 37. A ledger that v0.1.3 wrote reads and verifies
  in this release unchanged, and no record is rewritten. Guests on Ubuntu 24.04 and Debian 13 showed it: the published
  v0.1.3 was downloaded without an account, its signature checked and installed, two runs were made, and release files
  built from this release's code were installed over it with the installer. The old runs' records and receipts verified
  with the new build, the old runs were listed and the old refusal read, the old chain log stayed the front of the new
  one, and the old rules file compiled and passed `tego rules check`. A new run was recorded, refused what its rules
  refuse and verified, and the old records still verified after it. `tego uninstall` then removed the programs and left
  `~/.tego` and `~/.config/tego` as they were. No dashboard or agent service was running during that update.
- The fields that revision 41 adds are optional and none is removed or renamed: `run_start.home` (the home the run
  resolved), `run_start.applied_limits` (the kernel limits the scope holds), the machine baseline block (when a
  baseline was configured), `run_start.contract_source.learn` (the history `tego rules learn` writes), and on a live
  block's gap line `live_block.addrs` and `live_block.addrs_more` (the addresses a block by name was enforced on) and
  `live_block.note` (a lift's note).
- An older build reading a new record. A v0.1.3 reader reads and verifies a revision 41 ledger: a test that runs v0.1.3's
  ledger and record code on a ledger this release wrote read every line and passed the chain check, and the record
  code accepted a lift line with a note. It ignores the fields it does not know, so it shows none of them. A v0.1.3
  launcher refuses `tego lift --note` in words. This build, in turn, refuses a ledger whose `record_minor` it does not
  list (36, 38 or anything above 41) as an unsupported revision. This was checked at the ledger and record layers
  with test code, not with the v0.1.3 command line on a ledger from this release.
- Your rules files. The contract schema stays at `version: 0`, and no field is removed or renamed. It gains two optional
  fields: `learn` (the history `tego rules learn` writes, never a grant) and `business_rules` (see Added). A rules file
  that compiled under v0.1.3 compiles unless one of these refusals applies: a rules file on a file system that
  anything outside Linux can edit; a grant or deny that Tego cannot keep across the other names of a path (the refusal
  names the file and the other name); a `net.ask` entry for a `unix:` socket that a built-in refusal always refuses;
  on WSL, a grant that would give a run WSL's Windows launcher; and a machine config layer that is unreadable or has
  the wrong owner or mode, which now stops launch and compile commands. `tego rules check` tells you which.
- Scripts. JSON `fix` and `next` fields name the new commands. Compare them with the new names, or keep calling the old
  commands, which still work.

### Record `v`
1 (`spec/record/v1`, record minor 41)

### Contract schema
0 (`spec/agent/v0`; from v0.2.0 fields are only added, `docs/VERSIONING.md` section 3)

### Kernel minimums
Linux 5.14 with Landlock ABI 2 or newer, which is Linux 5.19 or a backport such as RHEL 9's 5.14; tested from 6.1 and on
RHEL 9 and 10, as AlmaLinux 9.8 and 10.2, with what ran where in `docs/TIERS.md` (tier 1: ABI 1 is unsupported,
and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
Syscall outcome hooks require readable tracefs event formats with an eight-byte `ret` at offset 16; unsupported
or unverified layouts withhold root tiers. The kernel version minimum is unchanged.

## v0.2.0-rc.1 - 2026-11-26

This is a release candidate for v0.2.0, with the changes listed under v0.2.0 above. It exists to rehearse the release
run: signed binaries, the container image, the published notes and the published download. Use v0.1.3, or wait for
v0.2.0, unless you are testing the release itself.

### Record `v`
1 (`spec/record/v1`, record minor 41)

### Contract schema
0 (`spec/agent/v0`; from v0.2.0 fields are only added, `docs/VERSIONING.md` section 3)

### Kernel minimums
Linux 5.14 with Landlock ABI 2 or newer, which is Linux 5.19 or a backport such as RHEL 9's 5.14; tested from 6.1 and on
RHEL 9 and 10, as AlmaLinux 9.8 and 10.2, with what ran where in `docs/TIERS.md` (tier 1: ABI 1 is unsupported,
and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
Syscall outcome hooks require readable tracefs event formats with an eight-byte `ret` at offset 16; unsupported
or unverified layouts withhold root tiers. The kernel version minimum is unchanged.

## v0.1.3 - 2026-11-13

This security release fixes file and command rules, record verification, and the handling of skipped kernel checks.
If you use Tego v0.1.0, v0.1.1 or v0.1.2, upgrade and restart your runs.
The v0.1.1-rc.1 prerelease is affected too.

### Security

- Denied reads at tiers cgroup and bpflsm: a host could already show a denied folder, or part of it, at another
  readable place on the same filesystem. A read through that place could miss the denial. This affects v0.1.0
  through v0.1.2. The fixed build refuses to start where the selected mechanism cannot hold the denial through
  those names. A decision plane still handles whole-folder names on the same filesystem where supported.
  Different filesystem instances that show the same data remain a limit. So do later host mounts, ancestor
  renames and rules that protect names rather than existing paths. Tier landlock keeps its stated alias limit.
  Hosts that already show a home or project folder at a second place, such as Fedora Atomic, toolbox and
  distrobox hosts, can meet this refusal where the selected mechanism cannot hold that second place;
  `tego doctor` names the places it found.
- Protected writes: in v0.1.0 through v0.1.2, a write or ask grant could reach kernel control files or Tego's own
  files through another existing mount. A user-writable Tego binary with another hard link was also exposed.
  An agent could change another run's controls or a binary used by a later run. Compile and run start now refuse
  grants that reach these protected places within the mount analysis's stated limits. Mount changes after compilation, separate
  filesystem instances and backing storage whose identity is not known remain limits. Keep that storage outside
  every write and ask grant. Processes outside Tego still have their ordinary rights.
- Command rules in v0.1.0 through v0.1.2 could miss some subcommand entries in `exec.deny` and `exec.ask` for
  systemctl, go, npm, pip and aws. It matters when the program may run and the contract relies on a subcommand
  entry. These command forms now match; some other tools refuse more commands where their parsing is
  uncertain. Whole-program refusals, file rules, network rules and ordinary OS privileges applied throughout.
  `exec.ask` is still reserved and refuses; it does not ask a person.
- Option-specific npm refusals could be missed, and some npm argument combinations could be admitted under
  an allow entry for another command. Command rules now check the command and options npm reads, including
  value assignments, option spellings and shorthands. Existing conservative refusals remain in place.
- AWS options written as assignments remain options when a preceding option needs a value. Missing values
  refuse constrained command rules; uncertain spellings retain conservative readings.
- Command entries containing an option terminator follow the tool's command, default command and argument
  boundaries. Unknown tools keep literal argument regions. Unestablished allow meanings and unsupported
  separator spellings fail to compile. Refusals of the compared inputs remain (the known limits below name
  one exception), and allow entries retain their prior limits.
  An allow entry does not admit its command when the command line puts `--` before the subcommand; write the command without it.
- This release decides command rules with two readings of each entry and command line: the corrected reading
  and a retained earlier reading kept as a floor. A deny or ask entry applies when either reading matches. An
  allow entry for a constrained program admits a command only when both readings do, and an allow entry the
  retained reading cannot interpret fails to compile, naming the entry. So some commands that an allow entry
  would admit under the corrected reading alone stay refused in this release.
- Known limits of command rules in this release. The reading that `tego compile` prints for a command entry
  is one of the two readings the decision uses; where they differ the decision is the stricter one, so
  the printed reading can show more than is allowed or less than is refused. An entry whose option word
  has an empty name is read as written; earlier versions could read it as a command's only long option, so a
  deny or ask entry written that way no longer matches that option, and compile does not warn:
  write the option's name. The comparison with the released matcher covers generated single-entry
  contracts and pinned cases, not every contract ([GAPS C72](GAPS.md)).
- Since v0.1.0, some Git command entries could miss a built-in run under one of Git's alternative names.
  Deny or ask entries naming `add`, `init`, `fsck` or `blame` were affected, as were entries for commands found in
  Git's helper directory but absent from Tego's command table. The fixed build applies those entries to the
  affected names in Tego's table and helper list. If you rely on these Git command rules, upgrade.
- Ledger roots outside `~/.tego`: versions v0.1.0 through v0.1.2 (including v0.1.1-rc.1) checked the ledger root's
  parent when deciding whether a write grant was inside a run's folder. With such a configured `ledger_root`, a
  grant inside an existing run's folder was not refused and could change that run's record and control files.
  Compile now checks the ledger root itself and refuses these grants, including through another mount of the same
  filesystem within the [compile-time mount boundary](adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary).
  This defect alone did not let the agent write its own newly created run folder: run start separately
  refuses a direct grant covering that folder. Upgrade if you use a ledger root outside `~/.tego`, and review write
  grants that reach existing run folders.
- Record verification in v0.1.0 through v0.1.2 could accept a record only as far as the line before an altered
  final line. This required write access to the record and no populated anchor entry for that run. Verification
  now checks a closed final JSON value and rejects malformed trailing content. An intact populated anchor
  remains necessary to detect a removed tail. An integrity check does not prove who made a record or that the
  actions in it were allowed.
- Kernel checks at root tiers: in v0.1.0 through v0.1.2, some preempting kernels could skip a program that should
  decide an action, without recording that loss. LSM checks were exposed before Linux 6.2, or before 6.1.54 in
  the 6.1 series, when kernel code could be preempted. The measured distribution defaults did not expose that
  older case. Exec pins were exposed on measured Linux 7.0 configurations. Listener cleanup could skip on
  preempting kernels. A run now reads the relevant skip counters. A detected
  decision skip ends a governed run with reason `error` and a gap saying its rules may not have held. An adoption
  reports the gap without ending the agent. Doctor withholds unsafe LSM modes and kernel exec assurance on the
  affected configurations. Exec pins and listener cleanup can still be skipped. Detection does not undo an
  action. Shared counters can end an unrelated run, and unmeasured vendor kernels remain a limit.

### Added

- In a terminal, `tego doctor`, `test`, `watch`, `learn`, `run`, `adopt` and `agents` end with a `next:` line on
  stderr that names the one command to type next. `TEGO_HINTS=off` turns these lines off, and `TEGO_HINTS=on`
  turns them on where stderr is not a terminal; they are never printed with `--json`. No stdout line changes:
  `tego doctor`'s Ready or Not ready line is on stderr, after its report.
- `tego learn <run> --save <name>` writes the proposed contract, compiled first, to the user registry, so
  `tego run <name>` finds it. It refuses a name that `tego run` would not find alone from the working directory
  or from the run's folder, a name that starts with `-`, and running under sudo for another user. The contract
  it saves has `reason: {reads: on}`, so a read the contract refuses is recorded at tier landlock too and a
  newcomer sees the refusal on every run; one line says what it costs (each read open about 17 µs slower), and
  `--reads off` leaves it out. The printed proposal, `--out` and contracts already saved do not change.
- `tego learn --allow-host <host>[:<port>]` (repeatable, at most 8) names the service a watched run reached at
  some of its addresses. Tego looks the name up now and writes `tcp://<host>:<port>` (`udp://` for UDP) in place
  of each address the run reached that the name resolves to. A later run is then allowed the addresses Tego's own
  lookups of the name return during that run, not only the one this run reached. An address no name may stand for
  (loopback, link-local, cloud metadata, or a range in the machine config's `denied_resolved_addresses`) stays an
  address. It writes nothing and exits 1 when the name does not resolve within 2 s, covers no address the run
  reached, resolves to a private address the run did not reach, or resolves to an address learn withheld after a
  secret read. It never chooses a name itself. When a proposal still allows addresses, stderr names them, and the
  `next:` line after `tego watch` and `tego learn` adds `--allow-host <host>`. The machine's resolver is never
  counted as an address to name (see Changed).
- After a run whose refused reads were not recorded, a `reads:` line on stderr says so, and
  `tego receipt --json` carries `reads_notified`.
- `tego setup` checks the machine from your shell and lists the six steps from install to an agent held by its own
  contract, each with the fact that decided it, then the one command to type next. It asks nothing, starts no
  program and needs no root; `--json` prints one object (`tego.setup/1`) and `-v` says where each fact was read. It
  stores its check in `~/.tego/state/check.json`, used only on the same boot with the same tego build; `tego doctor`
  still writes nothing. The installer ends with the one next command: `tego setup` when the installed tego has
  it, else `tego doctor`. `tego status` with no runs names `tego setup`.
- `tego receipt --json` adds a `binding` block: the run, its line count, its last line's id, whether it ended,
  the size and sha256 of `events.jsonl`, the tego that made the receipt (`receipt_by`) and its limits. No other
  key changes; a script that compares two receipts of one record across tego versions sees `receipt_by` differ.
  Binding checks every line as `tego events --verify` does, so on a long record `--json` takes 2.5 to 3 times
  as long (20,002 lines: 0.6 s against 0.2 s); the text receipt does not bind.
- `tego receipt --check <receipt.json> <run folder>` compares a kept receipt with a copy of its record on any
  machine, without chain.log: exit 0 match, 1 mismatch, 2 usage, 125 could not check (an older receipt, or a
  tego other than the one in `receipt_by`). It does not show that the record is complete or who made it, and
  anyone who can write both files can make a pair that matches.
- Dashboard: a finished run's Tighten tab has "Make a contract from this run". New contract, From a run, saves
  the draft where `tego learn <run> --save <name>` saves it (`~/.config/tego/agents/<name>.yaml`), through the
  same writer and with the same refusals, so `tego run <name>` in the run's folder and the `tego-agent@<name>` unit
  find it; "The project folder" still writes `agent.yaml` there. For the same run the file is the one
  `tego learn --save` writes, but for the header's `leaks:` line: the dashboard judges leaks by the run's verdict,
  not by learn's rule, so it has no such line, and for a run that leaked secrets the two can allow different
  addresses. A "Show refused reads (slower)" switch writes `reason: {reads: on}`: from a run it is on by default,
  as `--reads on` writes it; from presets it is off by default. Each address in a draft from a run says to write
  the host name. The dashboard now says the command line's words: Contracts, not Policies (nav, page titles, New
  contract, the Glossary), and Refused, not Blocked, for what a rule stopped, on the line page, in the built-in
  rules' names and in screen-reader labels too; Block now and live blocks keep their names. Addresses stay
  `/rules`, and `/contracts` leads there.
- At tier landlock a `deny_read` lets the agent read only the names each directory above the target held when the
  run started, so a file or directory made directly in one of them later cannot be read until the run ends; with
  the built-in `~/.ssh` entry, a new top-level entry in `$HOME` is one. Nothing said which directories those were.
  Now `tego run` prints one `note:` line naming them before the agent runs, `tego compile` prints the same note,
  `run_start` records them as `deny_read_frozen` (record minor 30), and `tego receipt` and the dashboard's Receipt
  tab name them under Coverage. What is refused does not change. A reader that does not know the field ignores it.
- `tego compile` notes an exec entry whose program file has more than one hard link, or is busybox, toybox or
  coreutils (`[exec-multicall]`, once per file, naming the entries that share it and its link count). On Ubuntu 25.10
  and later most coreutils commands are one such file, and an entry for one name can admit more than that name: at
  tier landlock, the file by any name to an agent that wins the exec race; on busybox, every applet at every tier.
  It changes no rule, exit code or `--json` table, and `tego run` prints it only with `-v`. `tego doctor` adds a
  `multicall` line on such a host, read from the file's link count and name. `docs/GAPS.md` C63 says what was
  measured.
- The dashboard's Overview shows the steps `tego setup` prints, in the same words: each step's state and fact,
  the one next step with its command to copy, and what is not known. It never checks the machine itself: it reads
  the check `tego setup` stored for this boot and this tego, and says "not checked since this machine started"
  without one. The dashboard also says what `tego receipt` says: the Receipt tab prints its sentences about
  connections and refusals word for word, a run's Refusals tab with nothing refused says the receipt's sentence
  (for a run that does not record refused reads, "No recorded action was refused", not "Nothing refused"), and a
  run's timeline, Refusals tab, Logs and Detections name tego's refusal of kernel TLS `built in: kernel TLS`, not
  "Not in contract". On the Logs page such a line says the receipt's sentence, not "not on the allowed hosts", and
  the Rule facet and By rule count it as `built in: kernel TLS`, as `tego receipt` does; a `rule:unmatched` query no
  longer lists it.

### Changed

- Compile and a root tier's run start now read the mount table through one strict reader. Compile reads the table
  twice and refuses one that changes while it is read, and it refuses a table whose mounts do not form one graph
  with a single root mount at `/`, as in a chroot whose root is not a mount point: every write and ask grant is then
  refused. Compile and `tego doctor` explain that the kernel does not show the filesystem under that root and give
  the remedy: bind the folder onto itself before entering it, or run Tego outside that root. A chroot whose root
  is a mount point, `pivot_root` containers, bubblewrap and `systemd-nspawn` retain ordinary grants. The kernel's
  unlinked-root marker is accepted only with a clean absolute prefix. Unlinked directory mounts remain uncertain:
  reaching write and ask grants refuse, and read-denial startup retains their alias uncertainty. Unlinked file
  mounts retain live protected-file identity checks under both files' snapshot mount IDs. An identity read error,
  failed holding-mount lookup, mount-ID mismatch or missing identity refuses reaching grants; established absence
  or a nonregular protected target needs no file comparison. An unplaced protected target keeps the backing warning.
  Several top candidates at the same mount point remain unknown before live selection, including mounts with the
  same parent and point, so affected grants and listener-decided denied reads retain their refusals.
  All captured and modelled tables in the compatibility inventory lack such siblings and keep their contract
  counts under replay; execution of the merged enforcement path remains owed in a guest.
  At run start, mount lookups are checked against the kernel's own mount ids, and overlay layers with a `..`
  component or an ambiguous `upperdir` or `workdir` spelling are not named there either.
- Record timestamps now follow the documented RFC 3339 profile. Newly refused forms are a comma fraction,
  a one-digit hour, offset hour 24 and offset minute 60. Every released Tego writer uses UTC with `Z` and an optional `.`
  fraction, so its records remain readable. A final chunk whose first top-level JSON value has closed is checked
  in full, including its suffix: non-whitespace suffixes are `line-malformed`; permitted JSON whitespace is
  complete and remains covered by the digest, so appended whitespace with a stale id fails. A refused timestamp
  is `line-malformed`, even without the final newline or with a stale digest; a suffix cannot hide it. Reader
  iteration, event views and receipt construction stop with a malformed-record error; receipt checking fails its
  chain step. The dashboard cache counts a terminated malformed line in `Bad` and continues. Its unterminated
  last bytes remain pending until a newline arrives, for valid and invalid timestamps alike.
- Tego v0.1.0 through v0.1.2 share a final-record framing flaw: a record whose last line was altered can verify
  only as far as the preceding line when no populated anchor for the run exists. An intact anchor entry detects
  the resulting head mismatch. Verification now checks a final chunk once its top-level JSON value has closed
  and rejects malformed trailing content.
- At tier cgroup without a decision-plane mode, a `setuid: true` contract with a `deny_read` or protected-name rule
  is now refused before the agent starts. The built-in secret list adds these rules, so ordinary contracts using it
  are refused in this combination. A setuid program can regain mount privileges and reach copied mounts outside
  the listener's marks. Remove `setuid: true`, or use a decision plane only where it holds the whole contract.
- Command patterns preserve option-name dashes beyond the usual one or two. Deny and ask entries keep the
  matches they had in the released build, except for an option word with an empty name (the known limits
  under Security), and also match the literal spelling; allow entries use only the literal
  spelling. Compile warns on more than two leading dashes or one dash before a long option name where the tool
  does not accept that spelling. Tool-defined single-dash long options and short words do not warn, including
  `go build -race` and `go test -run Test`. Tools without a known row keep literal single-dash option words,
  including `find -name file` and `java -jar app.jar`. The warning shows the entry and the ordinary spelling it
  probably meant. Use that spelling now; a later minor version will reject warned entries.
- Allow patterns cannot name selectors the command table discards, such as a Cargo toolchain or a gcloud release
  track. Remove the selector only when every variant may run. Deny and ask entries still cover every variant.
- Unique negated long-option abbreviations now keep their negation. The allow entry `git add --no-f` is now valid;
  a contract containing it previously failed to compile. No shipped example or preset uses these spellings.

- `tego learn`'s proposal opens with a `# WARNING:` line when it allows addresses, since a later run can be
  refused a connection this run made, and writes an entry by host name where the run's record holds the name an
  entry allowed. YAML keys are unchanged.
- `tego learn` no longer lists the machine's resolver in `net.allow` when the proposal has another TCP or UDP
  entry: port 53 of an address where every line of the run's record says `net.resolver`, such as
  `udp://10.0.2.3:53` on AlmaLinux 9.8. A comment under `net:` names what was left out. A run under the contract
  still reaches its resolver, because Tego allows the run's own resolver (from `/etc/resolv.conf`, or the machine
  config's `resolver:` list) before it reads `net.allow`. The entry was not needed where the contract was learned,
  and copied to another network it allowed whatever answers at that address. With no other TCP or UDP entry (a run
  that only looked names up), learn keeps the resolver as before, with a note: without any such entry the kernel
  layer opens no port 53, and from Linux 7.2 (Landlock ABI 10) it may refuse a lookup the run sends over UDP. TCP
  lookups pass, because Tego makes the allowed connect itself (measured at Landlock ABI 4 and 6). A run is now
  refused that address where it was allowed before only when learn left it out and the run's resolver is a different
  one (another network, a changed `/etc/resolv.conf` or `resolver:` list) or the contract sets `net.dns.mode: off`
  or `broker`. Port 53 of an address with any other line in the record is still proposed.
  `--allow-host` with a name that stands only for the resolver now exits 1 and writes nothing.
- `tego adopt --boundary`, and a boundary guard, applies a `cpu`, `cpu_weight` or `pids` limit (the machine config's
  ceiling, or the contract's own) to the agent's cgroup before it moves the agent: the agent is throttled, and a fork
  or a new thread past `pids` fails with `EAGAIN`. The kernel ends no process for them, though a program that cannot
  start a thread may end itself. `tego adopt`'s notice before the adoption says them; a guard does not. It is refused
  (exit 125, `[adopt-refused]`), with nothing moved, when the machine's cgroup root does not enable the controller
  (`cpu` on a stock RHEL 9: the message names the setup), and when the agent's tree holds as many tasks as `pids` or
  more, since its next fork would fail at once: the message gives the count and the limit. A `memory`, `memory_high`,
  `wall` or `stall_after` ceiling still refuses it, named at its file and line: every `tego run` gets that ceiling,
  and an adoption cannot hold it. A budget ceiling (`tokens`, `cost_usd`, `repeats`) does not refuse it: one
  `[unenforced]` warning per budget, and the run records that the budget was not metered. A record-only adoption
  applies no limit, goes on, and warns once for each ceiling. The record does not yet say which limits an adoption
  applied.
- Dashboard: the `landlock-topology` refusal reason reads Run boundary, not Sandbox boundary. The reason code is
  unchanged.
- The sentence that tells an agent about a `landlock-topology` refusal says "it reaches a process outside this run",
  not "a process outside this run's sandbox". The reason code is unchanged.
- `tego doctor`'s capability row `deny read of secret paths` at tier landlock now says that held reads, the
  default, refuse a target under a writable parent, and that `fs.reads: direct` leaves it unenforced. It said
  only "unenforced under a writable parent", which held reads made untrue before v0.1.0. What a run does is
  unchanged.
- Released command rules missed some name interpretations of a multicall program (one file under many names,
  such as uutils coreutils on Ubuntu 25.10 and 26.04). v0.1.3 expands `exec.deny` and `exec.ask` matching to the
  names such a program can pick its behaviour from; `docs/spec/exec-command-rows.md` ("Multicall applets by
  name") states what the matcher reads. Build-specific limits remain: Ubuntu 26.04.1's patched uutils
  refused the affected interpretations (measured); upstream uutils, read from its source, supports them.
  `exec.allow` does not read these names. A deny entry still wins over an allow entry, so a contract
  that denies a utility name may now refuse an exec that an allow entry admits, when one of the exec's names reads
  as that utility.
- A Locked run (the default, and the only mode at tier landlock) is no longer loosened by a live MCP tool switch
  or model route. `tego mcp allow` or `ask` past the contract's decision, `tego route set` to any route but
  `direct`, and the same changes on the dashboard's MCP tools and Model routes pages are refused with `[locked]`
  (exit 1) and the words a lift of a Locked run gets. A tightening, `tego mcp reset` and `tego route clear` still
  apply, and both kinds of change still loosen live on an Adjustable run. The relay and the forwarder do not check
  the mode themselves, so a change written into the run's folder another way still applies
  ([GAPS C39](GAPS.md)). The sentence every Locked refusal prints, `tego lift`'s included, now reads "`<run>` is
  Locked: it keeps to its contract while it runs, so nothing loosens until its next run"; it named the kernel,
  which holds neither a tool switch nor a route. The dashboard's preview of a refused change says "Not done: ",
  as its flash does, and links back to the page.
- In large Docker images and rootless Podman with FUSE, the optional Claude Code refusal hook may not be set up.
  The run continues with a `harness-hook-refused` warning. Refusals remain available through the reason file.
- A command rule's decision uses more memory. An exec of a program that command entries name is now read by two
  readers, the corrected one and the one earlier releases used (see Security above). Against v0.1.2's code on a
  hosted CI runner, the bytes allocated per decision rose by 10.5% for a script, 16.2% for a command with 16
  arguments and 17.4% for one with 128. An exec of a program no command entry names is unchanged, and a decision's
  time stays inside its documented budgets ([BENCHMARKS](BENCHMARKS.md)).

### Fixed

- Refuse root-tier runs whose compiled `deny_read` path entries have an existing mount alias on the same
  filesystem instance that the tier cannot hold. At tier cgroup where the fanotify listener would decide reads, a run
  now refuses to start when a denied folder, or part of it, is visible under such another name. No flag
  overrides this. A selected decision plane still holds whole-folder aliases on that same instance; a part
  mounted outside its denied folder refuses at bpflsm and at cgroup after fallback. The error names the first
  matching paths and places, counts the rest, and gives remedies. Doctor names visible second places for home
  or other built-in protected targets and the affected mechanisms. When an unlinked directory or unclassifiable
  root prevents a complete alias answer, doctor names the mount and says it cannot tell whether the folder is
  visible under another name. Known alias warnings remain, without assurance for the uncertain tree.
  A different filesystem instance showing the same data, such as a second network mount of one export, a FUSE
  mirror or a loop image, is not recognised at any tier. Deny the other path too, or avoid mounting the
  same export twice where agents can read it. For
  recognised network mount types, the same source string on different filesystem devices produces a warning,
  not a refusal. Name-entry scopes receive no alias check. Later host mounts and ancestor renames are not
  tracked (docs/GAPS.md C68).

- Compile and run start preserve carriage returns at the end of overlay layer options. The previous reader
  silently changed those names and could admit write or ask grants through a backing alias when a decoy path
  without the carriage return also existed. The snapshot size bound now counts actual input bytes.
  Binary overlay layers with a parent (`..`) component or ambiguous backslash quoting in `upperdir`/`workdir`
  now refuse write and ask grants, rather than compare a changed path. Use absolute layer paths without those
  ambiguities or install Tego on a plain filesystem. These kernel layouts are owed in a guest.

- Compile's mount analysis now follows the precise [compile-time mount boundary](adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary).
  Same-point stacks use parent relationships and supported live checks, including when a mount moved onto another
  appears earlier in mountinfo. Ambiguous visibility refuses affected write and ask grants and names the mount point.
  An unreadable mapped overlay layer candidate refuses rather than disappearing. Malformed mount rows refuse the
  table. Unknown protected or grant identity and binary candidate inspection errors also refuse with a named remedy.
  Ordinary host, CI overlay and workspace-volume fixtures each retain 19 accepted contracts, with exactly 11 volume
  warnings; project-with-chroot retains 17. Privileged moved-mount checks are owed in a guest.

- Compile now holds any `tego` or `tego-control` in `~/.local/bin`, `/usr/local/bin`, `/usr/bin` and `/opt/tego/bin`,
  beside the running and PATH binaries. Alias and binary overlay layer coverage is exactly the
  [compile-time mount boundary](adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary).
  A binary with a second hard link refuses every write entry on its filesystem, unless only root may write it and
  the agent is not root. Install a fresh copy with one name outside every write entry and run that one. An absent
  host layer alone refuses no grant, regardless of merged ownership. Relative overlay layers and unnamed FUSE,
  eCryptfs, aufs or shiftfs backing have the same stated limit; closure bounds still refuse grants. A write entry over
  a PATH folder searched before tego stays a `path-shadow` warning.
- A paused run whose launcher died (killed, crashed, out of memory) read as plain `lost`. `tego status` now says its
  last recorded state was paused and reads its scope for what is true now: STATE `lost, frozen` only when the scope is
  frozen, and the line under the table says when it is not (a stop thaws a run before it signals, so a launcher killed
  during a stop's grace leaves a run whose record says paused and whose processes run). `--json` adds
  `launcher_gone` and `scope_now`. `tego pause` and `tego resume` refuse such a run (`[lost-paused]`), and Tego never
  thaws it. `tego stop` attempts cleanup with `cgroup.kill`, reads the scope again and says what is left. For this
  lost-paused case it succeeds (0) only after record closure and a final scope read confirming absent or empty.
  Remaining frozen/running processes give `[lost-paused]`, 125; an unreadable final scope says "cannot tell" and
  uses the same status. The dashboard shows "Lost,
  last recorded paused". At tier cgroup and bpflsm the run's reaper already ends such a run at once. A launcher is
  judged gone by its lock and its pid's start time, never by the pid alone; one whose identity cannot be read is no
  longer taken for gone by `tego stop` and the sweep, and an exited launcher not yet reaped is. Sweep also keeps an
  unreadable scope, failed cgroup-id read or failed events read unknown, retaining its record and retry entry until
  cleanup can be confirmed. Retention reclassifies each run through its locked directory before choosing cleanup,
  including a run that started and lost its launcher after an empty sample. Unknown ledger state also keeps the
  record for retry even with a free lock; restore access or repair the record, then repeat GC.
- **Behaviour change:** compile now reads the mount table, and refuses a write entry or ask scope that reaches a
  kernel interface filesystem (proc, sysfs, cgroup, bpf, mqueue, resctrl and the others the docs list; devpts allowed
  only at `/dev/pts`)
  by its mount type, or an alias of one of Tego's own places or a directory read on its path walk, including names
  before `..`, within the [compile-time mount boundary](adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary).
  Terminal opens through aliases outside `/dev` are also refused by device identity. It read only the usual mount points by name, so a bind
  mount or a second mount of the cgroup filesystem inside a write entry let a run change other runs' cgroups, a
  paused one's freezer included. Ordinary triggers: a container's or chroot's root with its own `/proc` inside the
  granted folder, and a grant on `/dev` itself (`/dev/mqueue` is mounted there). A mount table compile cannot read
  whole and parse strictly refuses every write and ask grant. A FUSE type alone adds a mount advisory;
  identified protected source places and aliases still refuse.
  An absent host layer path (ENOENT or ENOTDIR), a relative overlay layer, or unnamed FUSE, eCryptfs, aufs or shiftfs
  backing alone refuses no write or ask grant. Ordinary grants compile in large Docker image, Podman FUSE and
  encrypted-home layouts. Tego never guesses where a relative layer lives; visible absolute layers and binary names
  remain protected. When a FUSE or eCryptfs filesystem holds a protected regular file, its existing absolute source
  directory joins the protected closure with its visible aliases: grants at, over or inside it refuse. Source text
  cannot establish FUSE backing identity; eCryptfs also keeps its backing warning because live lower-directory identity is not established.
  `..` and ambiguous upper/work quoting still refuse. With any of these backing limits, compile
  emits one `overlay-backing-unknown` warning per write or ask entry that reaches another visible storage mount. For
  relative layers and unnamed backing, another binary's device can still hold the backing folders; only the affected
  filesystem's own device is excluded. All cases exclude the shared inventory's kernel interfaces and memory
  directory storage; regular-file binds established by live checks can still warn on memory filesystems. The absent-only rule also
  excludes discovered binary overlay devices. Runtime storage on a memory filesystem mounted at a writable
  directory gives no warning (GAPS C65). A single-file mount is exempt only for absent or relative overlay backing,
  after live snapshot-bound mount ID, type, size and protected-file difference checks. FUSE/eCryptfs binds never get
  this exemption: stored bytes can differ from visible bytes. Nonempty byte-identical protected-file aliases still
  refuse, executable or not. Two empty files prove neither identity nor difference and warn without a byte-alias
  refusal. Agent fixtures keep Docker's `/etc/resolv.conf`, `/etc/hosts` and `/etc/hostname` binds quiet in the overlay
  classes with replayed `statx` IDs; runtime silence is owed in a guest. Captured Podman FUSE project grants reach
  no file bind; grants reaching one warn once, including empty `/run/.containerenv`. Unreadable protected files and
  unknown or changed mount points get no file-bind exemption. The warning names the grant, mount and each
  protected file directly on unnamed backing, including a config layer or a contract on sshfs even when Tego
  itself is on ext4: Tego cannot
  tell whether that mount shows the folders holding protected files, with the relative-base or filesystem reason. Keep
  runtime storage and the whole host filesystem out of writable places. For unnamed backing, keep the folder that
  stores the encrypted or mirrored files out of every write grant. No such grant and mount
  means no backing warning; a separate mount advisory may still print. A differently spelled alias may remain
  uncorrelated. Runtime fixtures now replay 2026-11-12 captures from Docker 29.1.3, containerd 2.2.1 and rootless
  Podman 4.9.3 with fuse-overlayfs 1.13 on Ubuntu 24.04, kernel 6.8.0-147-generic. They cover mixed relative lowers
  and absolute upper/work, real option tails and `fuse.fuse-overlayfs`. The alternative `fuse.overlayfs` remains
  synthetic. Capture runs used older head `69541c0706dd39125a004cc60f7ec046898e63be`; this branch's container
  reruns are owed in a guest.
  The dashboard describes historical paused orphan ends as record closure; those ledger lines alone do not prove
  which cleanup method ran. Stop output also reports record closure without claiming a kill, then reads the scope
  again and says what it shows after the sweep. Record closure alone does not make a lost-paused stop successful:
  processes remaining or an unreadable final scope give `[lost-paused]`, 125.
  "Why compile now refuses my grant" in `docs/user/built-in-refusals.md` explains the warnings and refusals.
  A run whose launcher cannot be judged now reads `(launcher unknown)` in `tego status`, with what
  to do, instead of plain running or paused.
- `tego doctor`, and a run's tier check where it probes the decision plane, could now and then fail a plane mode's
  known answers with "hold /proc/<pid>/root/.../x/xd: no such file or directory" and so not offer that mode. The
  probe's child makes its own mounts on the thread its main is locked to, and doctor sees them through
  `/proc/<pid>/root`, which shows the main thread's mounts only; when Go had moved the child's main off that thread
  first, the mounts were not there. The child now always runs on its main thread, and refuses to start, with the
  reason, if it is not. Seen once in a KVM root suite; a guest test showed the cause by forcing the child off its
  main thread. v0.1.1 has the same flaw (read from the code).
- Over SSH and on a console login, the `next:` lines no longer loop (`tego setup` named `tego doctor`, which named
  itself). Such a login starts outside your user manager's cgroup, where Tego starts no run, not even `tego watch`.
  `tego setup`, `tego doctor`, `tego run`, `tego watch` and `tego test` now say so and name the command that opens
  a shell inside it, `systemd-run --user --scope bash` (your login shell when it is bash, zsh, fish, sh, dash, ksh,
  mksh, tcsh or csh and on `PATH`), and then to run `tego setup` or the command again there. `tego learn --save`
  and `tego agents` do the same where their next step would start a run: they say that command, to type in the
  new shell. Tests check, from an SSH login, a console login and such a shell, that no `next:` line names the
  command that printed it or one that fails from that shell (see the next entry for two more places). `doctor` no
  longer says such a shell "can only record", and `tego test` no longer says "Nothing got through" when no run
  under Tego started. After a reboot, `tego setup` says which place is not checked since the machine started.
  With several contracts, step 5 names the one your newest enforced run used. `tego learn`'s refusal of an
  `--allow-host` name ends with the command without it, and the learn step names `--allow-host` only when no
  secret of the run may have gone to an address it reached, on `tego watch`, `tego learn` and `tego setup` alike.
  Saved contracts call themselves a contract in their header. The dashboard's "Make a contract" opens New
  contract from that run in one click, and its sign-in text names `tego serve`.
- Four more things a new user met (a second guest walk on Ubuntu 24.04, AlmaLinux 9.8 and Fedora 44):
  - `tego learn` for a run that read a secret and then connected out withholds that destination, and its warning
    still said `Name each with --allow-host <host>`, which learn then refuses for that host. The warning now says
    which destination was withheld and why, and the two ways that work, both your own choice: write the host's
    name under `net.allow` in the saved file, or, after a run under it is refused that connection,
    `tego rule <run> <line> --allow`. Nothing re-admits it by itself.
  - On Fedora 44, `sudo "$(command -v tego)" agents` typed inside a `systemd-run --user --scope` shell sent you to open that shell
    again, since sudo there opens a session of root's own. Tego now reads the cgroup of the shell you typed sudo
    in (the nearest parent outside root's own sessions), so from inside the scope it names the step itself, to
    type without sudo. Unit tests check this; it has not yet been run on Fedora.
  - A user with no user manager running (a nologin service account reached with `sudo -u` or `su -s`) was told to
    enable systemd user delegation, and `tego setup` and `tego doctor` named each other. Both now say no user
    manager runs for the user and name `sudo loginctl enable-linger <user>`, with the user's name from the passwd
    database (or the uid, when loginctl would read the name as an option or a uid). On Fedora 44, after that
    command, `tego setup` in the user's scope said `ready: tier 1 (landlock)`. Once the manager runs, a shell that
    has no `XDG_RUNTIME_DIR` (after `sudo -u` or `su`) is no longer left with no command: when `/run/user/<uid>`
    is the user's and holds its manager's socket, the `next:` line is
    `XDG_RUNTIME_DIR=/run/user/<uid> systemd-run --user --scope bash`. Unit tests check these lines; they have not
    yet been run in a guest.
  - For the few seconds before a run's first record line is written, `tego mcp allow`, `tego lift`, `grant`,
    `restore`, `route set`, a timed or read or write `tego block`, and the same dashboard actions said the run is
    Locked (or was started by an older tego). They now refuse with `[starting]`, "... is still starting ...; try
    again in a few seconds", and write nothing; the same command worked seconds later. A first record line that
    is there but is not one this tego can read (a damaged line, or one a newer tego wrote) is refused with
    `[start-unreadable]` instead, with no "try again", since waiting does not change it.

  Tests now also check `sudo "$(command -v tego)" agents` from an SSH login and from inside the scope, and the user with no user
  manager, before and after linger: no `next:` line names the command that printed it, a shell inside the user
  manager is not sent to open one, and `tego setup` and `tego doctor` do not name each other. The `sudo` cases are
  built from the cgroups the guests logged; on Fedora 44 only the command's own cgroup was logged, so the cgroups
  of sudo and of the shell it was typed in are assumed from how sudo opens root's session. Places outside those
  tests are not covered.
- Two more lines for a service account (a third guest walk on Ubuntu 24.04, AlmaLinux 9.8 and Fedora 44):
  - After `sudo loginctl enable-linger svc`, `sudo -u svc -H sh -lc 'exec "$(command -v tego)" setup'` named `XDG_RUNTIME_DIR=/run/user/<uid>
    systemd-run --user --scope bash` and did not say to run it as `svc`. Typed by the administrator in their own
    shell, it opened the administrator's own shell (where `tego setup` then said ready, for the wrong user) on Ubuntu
    and AlmaLinux, and failed on Fedora. When tego was started from another user's shell through `sudo` or `su`, the
    line is now `sudo -u svc XDG_RUNTIME_DIR=/run/user/<uid> systemd-run --user --scope bash`, the name from the
    passwd database and the uid as a number, and the words say to type it in your own login shell and that it opens a
    shell as `svc`, not in yours. `tego doctor`'s `fix:` line and the error line of `tego run`, `watch` and `test`
    name the same command there; before, they named the bare `systemd-run --user --scope bash`. Tego tells that from
    the session's login uid and the owners of the processes above it, not from `SUDO_UID`. Typed by `svc` in its own
    login, the line is as before. A passwd name that starts with `#` (which `sudo -u` reads as a uid) or `+` is
    written as the uid. `tego setup --json` adds `as.scope_as`. That `sudo -u` command, with `tego setup` in place of
    the interactive `bash`, was run in the guests and ran `tego setup` in `svc`'s user manager, ready at tier 1. The
    new words and the choice between the two lines are checked by unit tests; a root test in a guest also ran the
    `fix:` line's choice over the real `/proc`, for a process started by one of another uid, not through real `sudo`.
  - For an account whose name systemd refuses (digits only, such as `4242`, among others), linger starts no user
    manager, and `tego setup` named the same linger command again. `tego setup` and `tego doctor` now say that
    systemd runs no user manager for this account's name, name no `next:` command, and say to run the agent as an
    account whose name starts with a letter. `tego setup --json` gives that step the new `next.rule`
    `check-no-manager-name`. The rules for names are systemd's (systemd.io/USER_NAMES). The digits-only case was run
    in a guest before this change; that the other refused names get no user manager is read from those rules, not
    run; the new lines are checked by unit tests only.
- `tego learn` writes the contract's `name:` in double quotes, as `tego init` does. An agent name that YAML reads
  as a number, a bool or a null (`123`, `true`, `null`) was written bare, so `tego learn --save 123` failed with
  "name must be a string" and `--save null` with "name is required"; both now save.
- `tego receipt` and `tego watch`'s `seen:` line no longer count glibc's `connect(AF_UNSPEC)` resets and the
  kernel's netlink socket as places the run connected to: the first watch of a Python fetch said `most: unspec`.
  They are counted apart as routine socket calls that name no place, as the dashboard already folded them, and
  the dashboard's Receipt tab shows the count. `tego receipt --json` adds `routine_sockets`, and `connections` and
  `connection_tries` no longer count these calls. A refused one, such as a send to an `AF_UNSPEC` address, is
  still counted and listed as a refusal.
- `tego run`'s summary, `tego receipt` and the dashboard's Receipt tab say that the refusal of OpenSSL's
  kernel-TLS probe (`setsockopt(TCP_ULP, "tls")`, refused under every `net:` section) is built in
  (`built in: kernel TLS`), not "not allowed by any rule": no rule can allow it. It still counts as a refusal,
  and `--json` is unchanged.
- `tego receipt` and the dashboard's Receipt tab no longer say "Nothing was refused." for a run that does not
  record refused reads (tier landlock with `reason.reads` off): they say no recorded action was refused and that
  refused reads are not recorded. `tego receipt --check` on a receipt whose `receipt_by` names no tego build says
  so, in place of blank version words; it still exits 125.
- `tego doctor` says when a machine limit ceiling uses a cgroup controller that is not enabled, so that every
  `tego run` is refused at start (for example `limits.cpu` on a stock RHEL 9 host). It names the ceiling, its
  file and line, and the fix. The tier it reports does not change.
- `tego doctor` on RHEL 9 (and Alma or Rocky 9): the kernel line no longer lists Landlock ABI 2 to 6 as missing
  when the kernel answers ABI 6. Its Landlock entries now come from the ABI the kernel reports, as the `landlock`
  line does, and it says "below the upstream tested floor 6.1.0". On a kernel without Landlock it lists every
  Landlock entry. As root, its `cgroup connect_unix` entry follows what the programs check found. For a user whose
  cgroup is not offered cpu, the cgroupv2 line and a refused run's message now start with the administrator's
  steps and say why the user cannot add `+cpu` alone. The tier doctor reports and its exit code do not change.
- The dashboard's Receipt tab of a running run shows its time taken as a clock in all three places (the top
  line, the tile and the chart's axis); the top line and the axis stood still while the tile ticked, and the tab
  was sent again for a change of seconds only.
- Tiers cgroup and bpflsm: a look at a build's lock (the linger timer's, a sweep's) let the lock go by closing
  the file, so a child that the same process started in that moment could hold it until its own program started.
  The timer could then find the build still held and wait one more `bpf.linger` before removing it. Each look now
  lets the lock go explicitly.
- A process reaped while Tego read its `/proc/<pid>/stat` is read as gone, not as a malformed file. The kernel
  writes that line with process group -1, which Tego refused as malformed since v0.1.0: `tego adopt --pid` then
  printed `read process <pid>: ... malformed stat line: pgrp "-1"` `[io]` where it prints `no process <pid>`
  `[adopt-refused]`, and tiers cgroup and bpflsm kept the slot of a launcher reaped during the check until the
  next one. The kernel writes the same line for a live process when a thread other than its leader runs `execve`,
  so the line alone does not say the process is gone. Tego reads the file again: no file means gone, and a live
  line is used. A line that stays this way after three reads is still refused. The stat parser also refuses pid
  0, which no kernel writes.
- The MCP relay and the HTTP ask hold also read `/proc/<pid>/stat` again when its line has process group -1, as
  above. While a thread other than the leader of the process ran `execve`, an MCP relay shim could be refused at
  admission or when its server started, and a held HTTP request could be refused with `ask-unavailable`. A gone
  process, and a line that stays this way after three reads, are still refused.
- The Claude Code hook sometimes told a refusal one request late (once on a CI runner, where the reason file still
  did not list it more than 70 ms after its ledger line). The reason file the hook reads was written after the run
  directory's copy, under one lock, so a slow write there could hold it back; it is now written first. What held it
  back on that runner was not measured, so this may not remove every case. A refusal can still reach the hook one
  request late, at every tier on a busy machine, because its ledger line can be written just after the agent saw the
  refusal; it is then told by the first later hook that finds it in the file, still once. A script that reads
  `$TEGO_REASON` right after a refused call should wait for the refusal to appear.
- On a machine whose core utilities are one program file under many names (Ubuntu 25.10 and 26.04, about 115
  names), the dashboard's "Also apply now" after removing a program such as `/bin/ls` from `exec.allow` refused
  every other name of that file in the running run too, `/bin/sleep` among them, though the new rules still allowed
  them. That block now refuses only what the run was granted under the removed entry: the file at the path the entry
  led to when the run started, by any name that reaches it there. Where a program the rules keep leads to the same
  file by the same path (busybox's links all lead to `/bin/busybox`), it still refuses that file, as before. A block
  you place yourself (`tego block <run> exec /bin/ls`, Block now) still refuses the whole file, and `tego block` now
  names a few of the other names it refuses and how to block one name. When a block refuses another name of its file,
  `tego run`'s summary, `tego receipt` and the dashboard say so: "/bin/sleep: refused, same program file as /bin/ls,
  which is blocked". Runs started by an older tego keep the old block until they end; restart them to get the new
  one. A tego older than this release cannot read such a block's file (overlay version 5): its `tego block` and
  dashboard say the file is invalid and change nothing on that run.
- At the root tiers a run now ends with reason `error`, a `bpf-decision-skip/shared-build` gap and a receipt that says
  its rules may not have held (`rules-uncertain`) when the kernel skips a program that decides its actions, which
  before went unnoticed; a run with no skip is unchanged. An adoption first reports after run_start, then at most
  once a minute plus polling and scheduling delay, without ending. Partial report retries keep only unwritten
  lines, and observed outage openings and recoveries are retained in order, even between reports.
  `tego doctor` no longer offers the plane's LSM mode (tier 3) on a kernel before 6.2 (6.1.54 in the 6.1 series) that
  preempts kernel code, whose BPF trampoline can skip LSM programs too, and on a kernel that preempts kernel code
  (every 7.0 kernel) it says exec rules on argv are best effort, so `exec.assurance: kernel` is refused there
  ([GAPS C53](GAPS.md)). It also warns that listener cleanup can still be skipped on affected or unproven kernels:
  skips are detected, and a detected shared skip ends launched runs relying on it; adoptions report without ending.

### Record `v`
1 (`spec/record/v1`, record minor 30)

### Contract schema
0 (`spec/agent/v0`; the field set may change without notice before v0.2.0, `docs/VERSIONING.md` section 3)

### Kernel minimums
Linux 5.14 with Landlock ABI 2 or newer, which is Linux 5.19 or a backport such as RHEL 9's 5.14; tested from 6.1 and on
RHEL 9 and 10, as AlmaLinux 9.8 and 10.2, with what ran where in `docs/TIERS.md` (tier 1: ABI 1 is unsupported,
and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
Syscall outcome hooks require readable tracefs event formats with an eight-byte `ret` at offset 16; unsupported
or unverified layouts withhold root tiers. The kernel version minimum is unchanged.

## v0.1.2 - 2026-11-11

This patch fixes one flaw in how command rules read long command lines. It changes no other code.

### Security

- Command rules (`exec.deny`, `exec.ask`, and `exec.allow` entries with words after the program): Tego decides a long
  command on its first part (32 arguments, or fewer when they pass 8 KiB) when the rest cannot change the answer. In
  three forms the rest could still change it, and the command was decided on its first part anyway, so it ran though
  its whole command line is refused:
  - python's `-m` as the last argument of the first part, with the module after it: an entry on the module, such as
    `deny: [pip install]` or a bare `deny: [pip]`, was not applied;
  - cargo's `--config` or gcloud's `--flags-file` after the subcommand: `--config` can define an alias that runs
    `cargo publish` under another name, and `deny: [cargo publish]` was not applied to it; under `allow: [cargo build]`
    such a `cargo build` ran, which Tego refuses because it cannot tell which subcommand runs;
  - options after the `-c` of sh, bash, dash, zsh or ksh, or after the `-e` of perl or ruby, enough of them that the
    whole command line cannot be resolved (more than 16 ways to read it), which Tego refuses.

  Present since v0.1.0: the new tests fail on trees of v0.1.0 and v0.1.1 (unit tests, not run in a guest). The file
  and network rules, and which programs `exec.allow` lets run at all, were not affected. If you rely on command
  entries in `exec.deny`, `exec.ask` or `exec.allow`, upgrade to v0.1.2. These commands are now read to their end,
  or until no later argument can change the answer. A command that would have to be read past 8192 arguments or
  128 KiB of argument text to be decided is refused (`args-unreadable`), where before it could be decided on its
  first part.

### Record `v`
1 (`spec/record/v1`, record minor 29)

### Contract schema
0 (`spec/agent/v0`; the field set may change without notice before v0.2.0, `docs/VERSIONING.md` section 3)

### Kernel minimums
Linux 5.14 with Landlock ABI 2 or newer, which is Linux 5.19 or a backport such as RHEL 9's 5.14; tested from 6.1 and on
RHEL 9 and 10, as AlmaLinux 9.8 and 10.2, with what ran where in `docs/TIERS.md` (tier 1: ABI 1 is unsupported,
and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
Syscall outcome hooks require readable tracefs event formats with an eight-byte `ret` at offset 16; unsupported
or unverified layouts withhold root tiers. The kernel version minimum is unchanged.

## v0.1.1 - 2026-11-11

This patch tightens the built-in refusals around an agent and checks the file identities and security labels
used for approvals. Receipts and the dashboard give more reliable results for long runs, `tego rules` brings the
rules view to the terminal, and release automation adds signed container images alongside the binaries. MCP tool
rules remain a preview, with the limits below.

### Security

- Tiers cgroup and bpflsm, on overlayfs: on kernels that have `file_operations.fop_flags` but keep FMODE_BACKING at
  bit 25 (RHEL 9.8, RHEL 10.0 to 10.2, Linux 6.10 to 6.13, and 6.12 stable before 6.12.105), the decision plane did
  not recognise an overlayfs backing file. An agent could map a file under a write entry readable and `mprotect` it
  executable, which lets it run that file's machine code although no `exec.allow` covers it. A direct executable
  `mmap` was still refused. Present since v0.1.0. The plane now recognises a backing file whether FMODE_BACKING is
  bit 24 or bit 25, which covers every kernel checked from 5.14 to 7.1. Measured on AlmaLinux 9.8 and 10.2 for a
  file already on the overlay mount: the old build allowed it and the new build refuses it. The other kernels in
  the list are read from their headers.
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
- The release is built with Go 1.27.4, which fixes GO-2026-6859 in net/http: an HTTP/1 server could crash when a
  handler reads a request body limited by `MaxBytesReader` while response headers are written on another goroutine.
  tego-control's dashboard is an HTTP/1 server on 127.0.0.1 and limits form posts with `MaxBytesReader`; it reads
  each form in the handler's own goroutine, before writing a response.

### Fixed

- On RHEL 9 (AlmaLinux 9.8 tested), systemd turns on the memory and pids controllers by default, but not cpu.
  `tego doctor` failed on that and found no tier, so every enforced run was refused, including runs with no
  limits, for a user and for root. Now only a run that sets `limits.cpu` or `limits.cpu_weight` is refused, at
  start, and doctor and the refusal give the one-time setup that turns cpu on (`docs/TIERS.md`, GAPS B15). A
  `limits.cpu` ceiling in `/etc/tego/config.yaml` gives every `tego run` a CPU limit, so with one they are all
  refused, although `tego doctor` still reports tier landlock for a user. Memory and process limits apply. For
  root, doctor's fix now names a CPU weight on system.slice instead of user@.service, because a hand-written
  `+cpu` in the root cgroup does not last under systemd.
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
- The user service template `examples/systemd/tego-agent@.service` sets `Delegate=yes`. On RHEL 9, once an
  administrator has added cpu to `Delegate=` of `user@.service`, this makes the user manager turn cpu on for the
  service, so its runs can use `limits.cpu`. An interactive run there needs the setup in `docs/TIERS.md` for CPU
  limits (GAPS B15).
- A rule change from the dashboard or `tego rule` on a contract whose text has a lone CR, NEL, LS or PS line break
  looked for each node after that break on the wrong line: it could panic, and a removal could take a comment on the
  next line with it. Such a contract is now written from its YAML tree, as is one in UTF-16.
- A YAML file where a merge key (`<<`) applies to a mapping with a list or a mapping as a key, such as `{<<,[]}`,
  made the YAML decoder panic instead of failing to parse. In the price table it stopped `tego run` and
  `tego measure` with an internal error, and in a contract, a registry entry, a run's saved `contract.yaml` or a
  workspace file it stopped the command or dashboard request that read it. Such a file is now read as one
  that does not parse: a price table is reported as unreadable, and cost is not estimated.
- The reader of `/proc/<pid>/stat` took a line that starts with a negative pid, such as `-1 (a) S ...`, as a process
  with that pid, where it already refused a negative parent pid, process group or thread count. Such a line is now
  refused as malformed. Linux does not write one.

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
RHEL 9 and 10, as AlmaLinux 9.8 and 10.2, with what ran where in `docs/TIERS.md` (tier 1: ABI 1 is unsupported,
and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
Syscall outcome hooks require readable tracefs event formats with an eight-byte `ret` at offset 16; unsupported
or unverified layouts withhold root tiers. The kernel version minimum is unchanged.

## v0.1.1-rc.1 - 2026-11-10

This is a release candidate for v0.1.1, with the changes listed under v0.1.1 in docs/CHANGELOG.md. It exists to
rehearse the release run: signed binaries, the container image and the published notes. Use v0.1.0, or wait for
v0.1.1, unless you are testing the release itself.

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

The first release. Tego runs an AI agent under a contract you write, a YAML file of rules for files, programs
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
