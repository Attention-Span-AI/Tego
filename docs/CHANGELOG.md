# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), one section per tag, each ending in the three
lines `docs/VERSIONING.md` requires so a reader can tell what a binary speaks without pulling it: Record `v` /
Contract schema / Kernel minimums. Versions: [Semantic Versioning](https://semver.org/), `0.y.z` until 1.0
(`docs/VERSIONING.md` section 1).

## Unreleased

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
- `exec.deny` and `exec.ask` command entries now also match a multicall program (one file under many names, such as
  uutils coreutils on Ubuntu 25.10 and 26.04) by the names it can pick its behaviour from. On a file of more than
  one link whose name is one uutils links its file under (such as `ls` or `rm`), or a file named `coreutils`, a name
  that ends with the tool's name (`xrm`, `uu-rm`, `rm.x`), and a name that ends with `utils` or `box` followed by
  the tool as the next word (`myutils rm -r`), are read as that tool. The longest utility name wins, so `readlink`
  is never read as `link`. This reads the requested path, the file's own name and argv[0], also for a `#!`
  interpreter and a program run through the dynamic loader. Before, `deny: [rm -r]` let 7 of 9 such forms through.
  On Ubuntu 26.04.1 the patched uutils ran none of them as rm (measured); upstream uutils, read from its source, runs
  them as rm. `exec.allow` does not read these names. A deny entry still wins over an allow entry, so a contract
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

### Fixed

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
  - On Fedora 44, `sudo tego agents` typed inside a `systemd-run --user --scope` shell sent you to open that shell
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

  Tests now also check `sudo tego agents` from an SSH login and from inside the scope, and the user with no user
  manager, before and after linger: no `next:` line names the command that printed it, a shell inside the user
  manager is not sent to open one, and `tego setup` and `tego doctor` do not name each other. The `sudo` cases are
  built from the cgroups the guests logged; on Fedora 44 only the command's own cgroup was logged, so the cgroups
  of sudo and of the shell it was typed in are assumed from how sudo opens root's session. Places outside those
  tests are not covered.
- Two more lines for a service account (a third guest walk on Ubuntu 24.04, AlmaLinux 9.8 and Fedora 44):
  - After `sudo loginctl enable-linger svc`, `sudo -u svc tego setup` named `XDG_RUNTIME_DIR=/run/user/<uid>
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

### Record `v`
1 (`spec/record/v1`, record minor 30)

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
  `maze` workspace file it stopped the command or dashboard request that read it. Such a file is now read as one
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
