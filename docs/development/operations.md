# Operations: engine notes

User docs: docs/site/. This file holds engine notes for contributors.

## Start-up and cold kernel checks (2026-11-17)

At tiers `cgroup` and `bpflsm`, a cold start can take several seconds before the command's first instruction.
Tego loads and attaches the actual programs its capability answer requires, exercises the decision plane, and
releases the probe's objects before starting the run. The run then loads programs against its own configured maps.
On some kernels, releasing a tracing link also waits for a kernel grace period. These checks already shipped in
v0.1.3. Tier `landlock`, including an explicit root launch at that tier, runs no BPF probe.

Initial five-sample cold medians, measured on 2026-11-17 in idle two-vCPU, 3-GiB KVM kernel guests
using the repository initramfs and host userland:

| Kernel / root tier | Cold to command entry | Warm, answer and build retained | Host one-minute load |
| --- | ---: | ---: | ---: |
| Ubuntu 6.17.0-41 / cgroup | 13.746 s | 0.081 s | 0.98–1.48 |
| Fedora 7.0.14 / cgroup | 8.207 s | 0.111 s | 1.70–2.24 |
| Fedora 7.0.14 / bpflsm | 8.846 s | 0.098 s | 1.76–2.06 |

Root landlock medians were 0.032 s and 0.030 s on those kernels; non-root landlock was 0.057 s and
0.031 s. These are measurements for those guests, not a startup bound. Actual-program verification, the
run's configured-map load and link removal still cost several seconds. A smaller stand-in or an omitted
decision exercise would establish less. Sharing loaded programs needs equivalent map configuration,
resource-failure behavior and ownership; no such handoff is established by this change.

A run's probe of the decision plane stops after the mode the machine's `bpf.plane` takes: under `auto` or `lsm`, once
LSM mode has passed every hook, fmod_ret mode is not loaded or probed, and the start-up check line says so. Selection is
unchanged, since under those settings LSM mode is chosen first whenever it passed. A failed LSM mode, `bpf.plane:
fmod_ret` and `tego doctor` probe both modes; a kept answer that holds LSM mode alone is not used by a run pinned to
fmod_ret, which probes. On a kernel that closes tracing links one grace period at a time, this removes the second
mode's removal waits from a cold start.

After about one second of an enforcing start, stderr prints `[startup-wait]` if preparation is still pending.
A fast start prints no wait note, and the timer ends before the command is released. The command keeps stdout.
Caller and contract prerequisites, the status-file directory and the chain anchor are checked before the kernel
probe; a request that those checks already refuse does not wait for a capability answer.

Successful root-tier probe answers live in root-owned `/run/tego`. They have no time expiry, but apply only to the
same boot, kernel, binary and BPF objects, relevant kernel settings, invoking user, capabilities, security labels,
namespaces and launcher cgroup. Reboot, upgrade or binary replacement, another user or a different service/scope
cgroup can make another start cold. Unreadable authority facts, an untrusted cache location or a seccomp-filtered
caller prevent reuse. A launch failure can discard an answer that it reused; capture-unavailable and
unmetered-budget refusals keep it. A fresh successful probe can leave its new answer after a later launch
refusal. Early caller/contract refusals neither probe nor update these answers. `tego machine check` always probes afresh.

The answer cache is separate from the default five-minute loaded-build linger. After that build is unloaded,
a cached capability answer can still be followed by the run's own program loads. A cached answer never exempts
preparation from checking its actual loads and attachments. Increasing cache scope or substituting a smaller
stand-in program would change what the capability answer establishes.

## The control binary, tego-control (ADR 0100, 2026-10-24)

The dashboard and the other control commands live in a second binary, `tego-control`, shipped and built with `tego` (`make build` writes
`bin/tego` and `bin/tego-control`). `tego serve` hands off to it, and `tego help` marks every command that does as
`(tego-control)`. Install the two side by side: tego looks for
`tego-control` in its own directory only, never on `PATH` or in the working directory. `scripts/install.sh` installs
both from a release (VERSIONING.md §5), and refuses a pair whose pin does not match.

- **What the handoff checks.** The file must be a regular file (not a link), owned by root or by you, not
  writable by its group or others, executable by you (the execute bit of your class: owner, group or others), and on
  a mount that allows exec, so `chmod a-x` or a `noexec` mount disables tego-control as it would any program; an
  ACL's named entries and a security module's exec rule on the file are not read. tego copies it into a sealed memfd, checks the copy's SHA-256 against the hash
  its own build pinned, and runs the copy, so changing or replacing the file afterwards changes nothing that runs.
  `tego version` prints that hash as `control_sha256`; `tego-control version` prints `sha256`, which must be the
  same, and the same version and commit.
- **Refusals** (one line on stderr, exit 125):

  | Code | Cause | Fix |
  |---|---|---|
  | `control-not-installed` | no `tego-control` beside `tego` | install the `tego-control` of the same release in tego's directory |
  | `control-unpinned` | a `tego` built without the hash (`go build ./cmd/tego`) | build with `make build`, or install a release |
  | `control-mismatch` | the file's hash is not the pin: another build or release, or a changed file | install the pair from one release or one `make build` |
  | `control-untrusted` | a symbolic link, not a regular file, another user's file, a group- or world-writable one, one you may not execute, or one on a `noexec` mount | `chmod go-w`; `chmod a+x` if it is meant to run; install on a mount that allows exec; or reinstall the file |
  | `control-as-root` | `tego <noun>` under sudo, or `tego-control` at euid 0 or with a capability | run it as yourself; `tego-control` never runs as root |
  | `memfd-noexec` | the kernel refuses an executable memfd: `vm.memfd_noexec=2`, or a security module's policy | `cat /proc/sys/vm/memfd_noexec` shows the setting as any user (`tego machine check` reads it only as root); as root, `sysctl vm.memfd_noexec=1` (or 0) |
  | `not-built` | `tego-control <noun>` for a service this build does not have yet (help names these on its "planned, not in this build" line, never as commands) | use `tego status`, `tego events`, `tego approve` and `tego deny` |

- **Process names.** A handed-off tego-control runs from a sealed memfd: `/proc/<pid>/exe` reads
  `/memfd:tego-control (deleted)`, and the process names itself `tego-control`.
- **Limits.** tego-control, and every process it starts, gets the soft open-file limit (`ulimit -Sn`) tego was
  started with; the raise Go makes inside tego does not carry over. A governed run's agent gets it too, at every tier.

## Privileged path (ADR 0042, 2026-10-05)

The sudo examples use the reader-shell lookup explained in [Protection levels](../site/tiers.md#how-tego-picks-a-level).
AlmaLinux 9.8's sudo `secure_path` is `/sbin:/bin:/usr/sbin:/usr/bin`; neither a home install nor
`/usr/local/bin` is searched by sudo itself.
For a service account, install both binaries in that account's `~/.local/bin` (the user templates use
`%h/.local/bin/tego`), or use a root-owned shared installation and adjust the units' `ExecStart` paths.
Never point a service account at a copy inside an administrator's private home.

A printed root command also checks the executable and every resolved ancestor up to `/`: owners must be
root or Tego's effective user. World-writable non-sticky directories and missing metadata give no command.
Directory group write is allowed for the effective user's private primary group, or a group with no
members and no passwd primary users, such as an empty Debian staff group. Bounded local passwd/group reads
and the standard-library account lookup determine membership; only files-only NSS sources establish an empty
group. When membership is unknown (directory services, unreadable or oversized files), only the effective
user's primary gid by id is allowed, and the folder must still be owned by that user or root. Known foreign
local members always refuse. This fallback cannot rule out an unseen account sharing that gid. Non-sticky
group-writable folders with an access ACL or unavailable ACL metadata also refuse: a named ACL writer need
not belong to that group. The executable itself must never be group/world writable.
A sticky ancestor such as `/tmp` protects a child owned by root or that user against rename by other users; it does not protect writable file contents. Install Tego in a folder only root or you
can write if a hint is withheld. This checks current permissions; root and the effective user remain trusted.
For root-run Tego, this can conservatively withhold hints for an invoking user's home installation.

A manual `systemd-run --user --scope bash` and Tego's automatic user scope inherit the caller's PATH.
They do not add `~/.local/bin`. For a command started by `sudo -u`, that is sudo's `secure_path` unless
explicitly set. A user service receives its user manager's environment, not a login shell's profile.
The agent template sets `PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin` explicitly; contract
`env.pass` still decides whether PATH reaches the agent. Name programs outside it by absolute path.

- **Tiers 2 and 3 need a root launcher.** That is `sudo "$(command -v tego)" run` on a host whose sudo users are its administrators,
  or (not built yet) a root unit or cron job that names the agent's account with `--run-as <user>`.
  Users who are not administrators run tier `landlock`; tegod, which would give them the root tiers, is built only
  on ADR 0042's trigger T1.
- **Granting sudo for tego is granting root**, as membership of the docker group is: the launcher runs as root over
  inputs the invoker controls (contract and profile files, the per-user config layer, the hidden helpers' argv). A
  sudoers entry limited to tego is not a boundary Tego supports, and a service account never gets one: an agent
  that escaped to that account would inherit root. The one exception (FEATURES I9) is a CI runner account that is
  already root-equivalent, on an ephemeral or dedicated runner VM.
- **Run the agent as a dedicated account with no sudo rights** once `--run-as` lands; until then `sudo "$(command -v tego)" run`
  drops the agent to the invoking user with that user's primary group alone, and with that user's `HOME`, `USER` and
  `LOGNAME` where sudo left root's.
- **Capability or setuid copies of tego are refused.** A launcher that gained privilege without being root (a
  `setcap` or setuid copy, a unit that grants it a privileged capability) exits 125
  `[privileged-path-unsupported]` for every command but `version`. A unit's incidental ambient capabilities
  (`AmbientCapabilities=CAP_NET_BIND_SERVICE` and the like) are cleared and the run continues at tier `landlock`,
  with one note.
- **`/run/tego` is root 0700.** A root launcher creates it so. A host that installed the old
  `packaging/tmpfiles.d/tego.conf` line (`d /run/tego 1770 root tego -`) must
  `chmod 0700 /run/tego && chgrp root /run/tego` and remove the line; until then root runs exit 125 with that fix.
- **Root units:** the agent runs in `tego.slice/.../run-<id>.scope`, not the unit's cgroup, so the unit's
  `MemoryMax=`, `CPUQuota=`, `TasksMax=`, `systemctl status` and `KillMode=` do not cover it; the contract's
  `limits:` do. `systemctl stop` reaches it through the launcher's SIGTERM forwarding, `stop_grace` and the reaper.
- **The ledger is tamper-evident against the agent, not against the launching user**: the chain anchor sits in the
  user's own `~/.tego/chain.log` (GAPS C9). A record the user cannot rewrite is ADR 0042's trigger T3.
- `users:` is honoured from `/etc/tego/config.yaml` only and read by nothing in this release; `privileged_binary`
  stays parsed and warns that it is not used.

## Adopting an agent that is already running (2026-10-06; ADR 0055)

`sudo "$(command -v tego)" adopt --pid <pid>` governs an agent that was started outside Tego, in any terminal or IDE. A running
process cannot be given a seccomp filter, Landlock or another environment, so this is root's and the kernel's: the
agent's own process tree, and nothing else, moves into a fresh cgroup,
`tego.slice/tego-<agent>.slice/adopt-<run id>.scope`, where tier 2's programs record from the kernel every program
it starts, every file it opens and every connection it makes, into a normal run: `tego status|events|drift <run>`
read it. The command prints whose process it is (real, effective and saved uid) and the run id, and holds the run until
the agent's tree ends (run_end `exit`). Ctrl-C, SIGTERM, `tego session stop <run>` or `tego adopt --release --pid <pid>`
**release** it: the tree goes back to the cgroup it came from and runs on, unrecorded (run_end `stopped`, naming who
asked). `tego session stop` and `--release` signal nothing: they leave a release request (`/run/tego/adopted/<run>.release`)
that this adoption alone answers, so a guard's other adoptions, and the guard, run on. If root moves the tree out by
hand, the run ends `stopped` and says so. An agent that was the only process of a transient scope (`systemd-run --scope
agent`, an app launched from a desktop) leaves that scope empty when it moves, and systemd removes it; every cgroup above a
scope has controllers on for its children and refuses a process of its own, so the release makes a new empty cgroup
`tego-released-<run id>` under the nearest cgroup above the origin that lets one be made (for a user's scope, the user's own
`app.slice`) and puts the tree there: no longer in a Tego scope. Under a user manager (the origin was below
`user@<uid>.service`, as for a desktop launcher or `systemd-run --user --scope`) the leaf is in the user's own part of the
hierarchy: a logout ends it as it would have, and it stays until that user manager stops (it is the user's `rmdir` to
make). Where the origin was directly under `user-<uid>.slice` (a session's own scope) or `system.slice` (`sudo
systemd-run --scope`), the leaf is root's in a root's slice: the user cannot remove it, stopping a user manager does not
remove it, and a session logout does not reach a process in it (remove it with `rmdir` as root once it is empty). The
properties of the origin unit (`MemoryMax`, device rules and the like, set with `systemd-run -p`) do not follow the tree
into the leaf, as they did not follow it into the adoption's scope. A process the release finds no cgroup to put back in, and no place to make one (the one it came from and every one
above it gone or refusing it, and none lets a cgroup be made) stays in the scope, released and unrecorded, counted by `gap
adoption-left-in-scope`; the scope and the adoption's record stay with it (the record marked released), `tego agents`
reports it governed by the ended run and the guard refuses it under `governed`, and `sudo "$(command -v tego)" adopt --release --pid
<pid>` moves it out once a cgroup takes it, then removes both. `--release --pid` acts only on a process in an adoption's
scope at its own place (`/sys/fs/cgroup/tego.slice/tego-<agent>.slice/adopt-<run>.scope`) that the run's record
names: a cgroup a user made with an adoption's name in their own subtree is refused, `[adopt-refused]`. A release request answered so is not a failure of the
adopter's: `tego session stop` and `--release` say at once that the run ended and how many processes stay in the scope, and
exit 1, rather than waiting 30 s for a record that stays. The same holds when an adoption fails after the move and
before it records (its tier's Prepare, or a boundary on a box with no plane mode): what moved goes back, and what no
cgroup takes stays in the scope with the record, which the error (`tego adopt`'s, the guard's `adoption_failed`
note) names; no run exists for it, so the later release writes no run_end. An adoption **never kills** the agent. It needs root of the initial user namespace and the BPF objects (`make build`); without
root it exits 125 `[privilege]`. The design, its evidence and its scope guard: ADR 0055.

What moves, and what is refused. The agent and its descendants that are still in the agent's cgroup move, the agent
first: never its parent shell, a sibling in the same session scope, or a descendant placed in another cgroup (a
`systemd-run --scope`, a container), which is counted in the record instead. A process the agent started that was
reparented away before the adoption (its parent exited, as a daemon's does) is no longer its descendant: it is not
moved and not counted. Refused outright, with the rule named
(exit 125 `[adopt-refused]`): pid 1, a kernel thread, a thread id, tego itself, any ancestor of the command (its shell,
sudo, sshd, a multiplexer, the user manager), a systemd manager (`init.scope`), a container's process (another cgroup or
pid namespace), a process already in a tego run or adoption, and a process in the root cgroup (a release never moves
a process into the root cgroup, so it could not be given back). Only the invoking user's own process is adopted
(the user sudo ran tego for; root's when root runs it directly): another user's needs its owner named, `--uid
<uid>` (repeatable), or it is refused under `uid` with the `--uid` that would admit it; a process whose real,
effective and saved uids differ is never adopted. A process is named by its pid and its start time: right before the
move, under a host-wide lock every adopter holds while it moves (`/run/tego/adopted/moves.lock`), it is read again and
every rule above is applied again, and before each process's own move its start time is read again, so a process that
exec'd, changed its user or was adopted by someone else meanwhile, or a pid that names another process by then, moves
nothing.
While adopted, the agent is outside its session scope: a logout's `KillUserProcesses` and the session's accounting do
not cover it until it is released.

What the record holds, and what it cannot. From the attach on: execs, opens (reads too, at the default `--record full`),
file creations, removals and renames, connects. Never: what the agent did before the attach (`gap adoption-pre-attach`
names the agent and counts its processes; each one's `exec` line, `by: adoption`, carries its start time in its
`exec_id`), reads, writes and sends through descriptors it already held, and loads and stores through files it had
mapped (`gap adoption-open-sockets` counts the sockets it held; a socket keeps the cgroup it was made in), its model traffic (the forwarder needs the agent's environment),
and a process of its tree that did not move (`gap adoption-not-moved`). The window between finding the agent and the
attach is 50-75 ms when another run, or the build's linger (5 min), keeps tier 2's build loaded, and 3.5-6 s on a cold
build (measured in a 2-GiB guest); everything in it is the pre-attach gap, never silence. A busy agent loses no event
silently afterwards: a full ring is a `ringbuf-full` gap with its count. The exit status of an agent tego did not
start is read from the kernel's process events when it can be (the agent's own exit, never a later process's under a
reused pid; the end of its last thread, and only a status every compared exit code agrees on, from the listing made
of it when it was adopted on), else run_end says it is unknown. Where a fatal signal or another thread's `exit_group`
arrives while a task is between its own `exit(2)` call and the start of do_exit, the kernel's events carry the task's
own code and `wait(2)` the group's: that window, a few hundred nanoseconds, is the one case the events cannot tell
(ADR 0055 (e), "racing exit").

A boundary. `tego adopt --pid <pid> --boundary agent.yaml` holds the agent to the contract's file rules and exec allow-list
through the kernel decision plane (fs.write and the refusal of every other write, deny_read with the built-in list,
exec.allow's programs), from the attach on. The contract compiles against the agent's owner's home from the passwd
database, so `~` and the built-in lists (`~/.ssh`, `~/.aws`, shell startup files) are that user's, whoever runs tego:
the guard compiles one table per `--uid` when it starts, and a boundary for a uid with no home there is refused. What
only tier 1's seccomp filter refuses is not held on an adopted process, whatever the contract says: System V IPC (even
without `ipc: true`), socket families outside the network rules (AF_VSOCK, AF_PACKET, SCTP and the rest), io_uring,
openat2, open_by_handle_at, clone3 and the terminal-input ioctls; the ledger has
`gap what=enforce adoption-no-syscall-filter`. The plane holds the mount topology by refusing `CAP_SYS_ADMIN`
in every user namespace: mount APIs and mount-namespace creation or installation are refused, as are other uses
of that capability. Creating a user namespace alone may still succeed but does not permit mounts. This starts
at the arm; earlier changes and changes by processes outside the run remain outside the guarantee. Each plane
refusal is a ledger line with `mechanism: plane` (rule `mount-topology` for this capability). It needs a plane mode on this
machine (`sudo "$(command -v tego)" machine check`: `decision plane: fmod_ret` or `lsm`); the fanotify fallback cannot refuse a write, so
there the adoption is refused. Every rule that cannot be added to a running process is refused before anything moves,
each one named: a `net:` section (a socket made before the adoption would not be governed, and the record could not
tell which), `fs.ask` and `ask`, `env`, `models` and `capture`, the limits an adoption cannot hold (`limits.memory`,
`memory_high`, `wall`, `stall_after` and the contract's budgets), `gate`, `mcp`, `docker`, a tier other than cgroup, a
`memory`, `memory_high`, `wall` or `stall_after` ceiling of the machine config (every `tego run` gets it, so each is
named at its file and line: a moved process's memory stays charged to the cgroup it came from, so a cap would count
only what it allocates after the move and would end it when reached, and a time limit ends it, which an adoption
never does), and every exec command rule: `exec.deny`, `exec.ask` and an `exec.allow` entry with argument words
are decided on argv by the supervisor, which an adopted process does not have (the plane decides which program runs,
never its arguments). A budget ceiling (`limits.tokens`, `cost_usd` or `repeats`) does not refuse an adoption, as it
does not refuse a `tego run` where nothing meters it: an adoption captures no model
traffic, so it warns `[unenforced]` at the ceiling's file and line, and its run records
`gap what=record why=budget-unmetered`. A record-only adoption is refused for no ceiling and warns of each one.
A `cpu`, `cpu_weight` or `pids` limit (the contract's, clamped to its machine ceiling, or the ceiling alone) is applied
to a boundary adoption (ADR 0055, limits amendment): `cpu.max`, `cpu.weight` and `pids.max` are written into the
adoption's cgroup before tier 2 is armed and before anything moves, and the notice says them (`limits: cpu 2, pids 512,
written to its cgroup before the move`). From its move on the agent is throttled, and a fork or a new thread past
`pids.max` fails with `EAGAIN`. The kernel ends no process for them, but a program that cannot start a thread may end
itself (Go and Node abort then). The adoption is refused (exit 125, `[adopt-refused]`), with nothing moved or left, when
the cgroup root does not enable the controller (`cpu` on a stock RHEL 9: the refusal names the setup, GAPS B15), and
when the agent's tree holds as many tasks (processes and threads) as `pids.max` or more, since its next fork would fail
at once: the refusal gives the count and the ceiling; raise `limits.pids` above that count or adopt with no
`--boundary`. A tree that grows to it while it moves is released where it came from and refused. A release that leaves
processes in the adoption's cgroup sets its limits back to the kernel's default, and run_end's detail says a lift
that failed. The record does not say which of the
three were applied (run_start's `limits` holds budgets only); `run_end.resources` counts `pids_peak` and
`cpu_nr_throttled` (GAPS C56).
`tego adopt` prints these warnings; a record-only guard prints each once when it starts, not once per agent; a
boundary guard prints the budget warnings at its start once for each `--uid` (GAPS C56).
A file the agent opened across a rule before the adoption stays open, and a file it mapped stays mapped
(`gap what=enforce adoption-open-descriptors` counts both, by the plane's own rows: a file held, or mapped at all,
where the plane refuses a read (any deny_read entry, the built-in list and its `.env` names included), and a file held
for writing, or mapped shared and writable or may-write, where it refuses a write: outside every write entry, or a
deny_write target beneath one, such as the repository's `.git/hooks` and `.git/config` or `~/.bashrc`. Under `/dev`
only the terminal and the byte sinks such as `/dev/null` are left out; `/dev/shm` counts; a file on one of the
superblocks the kernel mounts for itself, such as a memfd, a System V segment, the AIO ring or hugetlb memory, is no
file a rule names and never counts, told by its device, which tego learns by making one of each; any other file
counts by its path, one held from a chroot included, by every other path that reaches it through another mount
of the same filesystem, such as a bind mount of a directory above it, by the path of a rule's file it is a hard
link of, since the plane decides a file's inode under every name it has, and by its path beneath a rule's directory
its name passes through under another name (renamed since the plane was filled): of the files `/proc` lists, the
count can be high, never low; the descriptors are every thread's, a thread that unshared its own descriptor table
included). A process whose descriptors or mappings could not all be read (more than 4096, or a listing that
failed, a thread's table included), one holding a descriptor `/proc` cannot name (a file open at a path longer than
`PATH_MAX`, which `readlink` refuses) or whose open flags it cannot read, one holding an io_uring instance with registered files (they are read and written through the ring with no
descriptor `/proc` lists), and, for a boundary, a process in a mount namespace other than tego's, one mapping an
io_uring instance it holds no descriptor of (on a kernel that puts every ring on one shared inode, any ring it maps),
or one holding a file whose name is no path of it in tego's
namespace (held through a detached clone or a lazily unmounted mount, which `/proc` names from that mount's root, so
`~/.ssh/id_ed25519` through a clone of the home reads `/.ssh/id_ed25519`; or a pseudo file such as a dma-buf, on a
superblock tego does not probe), is counted in `gap adoption-descriptors-unread`. What `/proc` lists of no process
is not counted at all: a descriptor in flight in a unix socket's queue (sent with `SCM_RIGHTS`, not yet received), an
io_uring instance registered with itself and neither held nor mapped, a file another kernel object holds. The agent owner's own `~/.tego` is read-denied
under a boundary as under the owner's own launched run, while the ledger and the chain anchor are the adopter's. A
boundary adoption makes that directory first when the owner has never run tego (mode 0700, owned by the owner), so
the records of the owner's first run are denied too, and refuses the boundary when `~/.tego` is not itself a
directory (a file, or a link, even one to a directory: the link would be under no row, so an agent allowed to write
the home could swap it for a fresh directory) or cannot be made, or when another directory was renamed in at that name while tego made
it (root gives the owner only the empty directory it made); an adoption keeps its table while it runs. Before it
arms, it checks that the plane's row for `~/.tego` is at the directory the table was compiled against (the
contract's own `deny_read` of it included), and once armed, that `~/.tego` is still that directory itself, no link
to it; it fails,
giving the agent back, when either is not so (the agent removed or replaced it in the moment before the arm; adopt
again). From the arm on the agent can no longer rename, remove or replace it. An owner whose
passwd home does not exist (a service user's `/nonexistent`) gets no home made and no such deny, as no records can be
there; nor does an owner whose home it may not write by its mode (a service account's `/` or `/var/www`, owned by
root): root makes no directory there, which the owner could not have made itself (a home only an ACL lets the owner
write counts as one it may not). The guard compiles a uid's table again before its next adoption when that uid's
`~/.tego` is no longer the directory the table denies, its missing home exists now, or a `~/.tego` appeared in a
home it may not write. A
boundary write entry at or inside the owner's `~/.tego` is refused (`contradiction`). Other built-in
deny_read paths made after the guard started (a new `~/.aws`) are covered from its next start: restart the guard
after setting up a user's credentials.

The guard. `sudo "$(command -v tego)" agents --follow --adopt --uid <uid>...` adopts each agent the detector reports outside every
governed run whose real, effective and saved uid are one listed uid, as it starts (or, when the guard starts, as it
is found running). Any local user can name a program `claude`, so `--uid` is required, and root's agents are adopted
only with `--uid 0`; any other agent is reported (`adoption_refused`, with the rule) and left alone. `--boundary` and
`--record` apply to every adoption. Its lines: `adopted` (pid, uid, run, how many processes moved, `window_ms`),
`adoption_refused`, `adoption_failed` (what moved went back, unless its note says which processes stay in the scope)
and `adoption_ended` (the run's reason). Each agent is
considered once and never retried; one process is never adopted twice; at most 32 adoptions at once, past which an
agent is refused and said so. Stopping the guard (Ctrl-C, SIGTERM, `systemctl stop`) releases every agent it adopted
before it exits. It is a foreground command (ADR 0042: no daemon); run it under
systemd to keep it running.

If the adopter dies. Its reaper, `tego __adopt-reap` in tego's `helpers.scope`, releases the agent, writes run_end
`orphaned` and removes the scope and the run's kernel state: killing the adopter leaves nothing attached and does not
kill the agent. If the reaper is gone too, nothing records the agent any more: it stays in the scope, and a boundary's
plane rows go on refusing what the contract forbids, with no ledger line for those refusals, until it is released.
`sudo "$(command -v tego)" adopt --release --pid <pid>` releases it from the adoption's record and writes run_end `orphaned` saying
who did; so does a root sweep (`sudo "$(command -v tego)" gc`), whose run_end `orphaned` has no detail and is written only after the
tree is out. Until then the ledger shows the run as lost (`tego status`), never ended: an unprivileged `tego gc`
leaves it lost and says only root can release it, and a process no cgroup takes back keeps it lost, record and scope
kept, for the next try. No sweep ever kills an adoption's scope.

Removing it as root, by hand. While a run is adopted the host holds: the scope (`/sys/fs/cgroup/tego.slice/*/adopt-
<run>.scope`), the record and a lock (`/run/tego/adopted/<run>.json`, `/run/tego/adopted/target-<pid>-<start>`, root
0600 in a root 0700 directory; a pending release request beside them; `moves.lock`, permanent and empty) and, in the build's pins, a run-set row (`/sys/fs/bpf/tego/<hash>/maps/tego_run_set`;
a boundary's plane rows too). Nothing is hidden. `tego adopt --release --pid <pid>` undoes it all; by hand: write each
id the scope's `cgroup.threads` lists into the `cgroup.procs` of the cgroup the record's `from` names (a thread's id
written there moves its whole process; the scope's own `cgroup.procs` leaves out a process whose main thread exited
outside it), `rmdir` the scope once `cgroup.threads` is empty (its run-set row goes with it), delete the two files, and
`sudo "$(command -v tego)" gc --builds` to remove an idle build.

## Host daemon sockets with no `net:` section (ADR 0070, 2026-10-25)
A contract with no `net:` section keeps every IP destination but reaches only the unix sockets the run itself bound
and Tego's own endpoints (the DNS broker's socket). Every other unix connect or addressed datagram, pathname or
abstract, is refused, `rule: host-sockets`, and the line names the socket and, for a well-known one, what it gives
(`what: the Docker daemon, root-equivalent`). What an agent may have used that is now refused:

- **git over ssh** (`SSH_AUTH_SOCK`), commit signing (gpg-agent), the `docker` and `podman` clients, the session bus
  (`notify-send`, the secret service, `systemd-run --user`) and an X display. Name the one socket the agent needs in
  a `net:` section, which then names the hosts it reaches too, since a `net:` section refuses what it does not name:

      net:
        allow:
          - "github.com:22"
          - "unix:/run/user/1000/ssh-agent.socket"   # the path SSH_AUTH_SOCK holds

- **glibc's lookups:** nscd (`/var/run/nscd/socket`), `nss-resolve` (systemd-resolved's varlink socket) and
  `nss-systemd` (userdb) are refused, and glibc falls back to `/etc/hosts`, DNS and the files, so name and user
  lookups keep working; the refused lines stay in the ledger (on a host with nscd configured, a refused connect for
  each process's first lookup).
- **Interface enumeration** (`getifaddrs`, `if_nameindex`, `getaddrinfo`'s `AI_ADDRCONFIG` source-address query;
  Node's `os.networkInterfaces`, psutil, Go's `net.Interfaces`) works, here and under a `net:` section (ADR 0128): a
  read-only `NETLINK_ROUTE` request to the kernel is relayed as the task, one allow line `dst family(16) proto raw`,
  rule `route-query`, per query. It lets the agent read the host's interface names and MAC addresses, every address,
  the routes and the neighbour table (the other machines on the LAN the host has talked to). That is always on, and most
  of it is in `/proc/net` and `/sys/class/net` anyway; ADR 0128 lists it. A message that changes the network is refused
  `route-change`. Any other netlink message (another process's port id, a multicast group, generic netlink such
  as nl80211 or ethtool) and an `AF_PACKET` socket are refused `host-sockets`. `host_sockets: true` restores them. A
  `net:` section does not: it refuses other netlink protocols at `socket(2)`, `EPROTONOSUPPORT`, so `ss` and `ethtool`
  fail there. Under `net.assurance: kernel` the C library's interface lists work wherever a decision plane runs the run
  (tiers cgroup and bpflsm with `decision_plane` lsm or fmod_ret): the plane's `socket_recvmsg` refuses only a receive on a
  unix socket that carries a control buffer (`EACCES`, a ledger line, rule `socket-import`), so a route socket's reply is
  read and no descriptor can be received; a UDP or TCP control receive passes with no line. A run that holds its opens
  (`fs.reads: held`, or `gate.completion: held`) is no exception since 2026-11-21: its open deputy, which receives with
  a control buffer, is passed by its identity alone (ADR 0128, amended). A run with no plane (tier landlock, or tier
  cgroup on the fanotify fallback) keeps the filter's `ENOSYS` for every `recvmsg`: `if_nameindex` and `getifaddrs` return `ENOSYS` and Node's
  `os.networkInterfaces()` throws there, as before; `tego rules check --test` says so under its tiers line. `getaddrinfo`
  goes on, and Go's `net.Interfaces`, which reads with `recvfrom`, works everywhere. `recvmmsg` and `pidfd_getfd` stay
  `ENOSYS`. A refused control-bearing `recvmsg` now returns `EACCES`, where the filter answered `ENOSYS`.
- **The opt-out** `host_sockets: true`, in the top-level contract only (a profile's is ignored,
  `profile-cannot-loosen`), restores the old reach: `rules check` warns at the key, naming each well-known daemon socket
  it finds here and what it gives, and run_start records `host_sockets: true`. Prefer the `unix:` entry.

At tier landlock the supervisor performs every connect of such a run on its own copy of the socket, every Fast-Open
send and every send on a connected stream socket, and every addressed datagram it can reproduce exactly. Measured with
`BenchmarkUnixOnlyRelay` on a shared development machine (i7-10870H, 4 CPUs, 5,000 calls, median of 3 runs, 2026-10-25):
an addressed UDP datagram (a DNS query) takes 56.7 µs relayed against 48.3 µs continued, +8.4 µs (supervisor 1,778 to
2,346 B and 18 to 29 allocations per call), and a TCP connect 108.7 µs against 102.7 µs, +6.0 µs (2,118 to 2,611 B, 26
to 34 allocations). A Fast-Open send, a send on a stream socket without a peer and an addressed send on a connected
stream socket (whose address the kernel ignores and no line records) are relayed at the same per-call cost as a
datagram rather than continued; an addressed send on a connected seqpacket socket stays continued (best effort), so
its receiver reads the sender's own pid. Descriptor passing is unaffected: it sends with no address. A resolver
that queries per request pays the relay per query. At tiers cgroup and bpflsm the same relay and Landlock carry the
restriction, best effort until the root tiers carry a kernel program for it (run_start `best_effort` `host_sockets/root-tier`).

## Model budgets need something to count them
A contract's `limits.tokens`, `limits.cost_usd` and `limits.repeats` are counted from the model traffic the run
captures, and `cost_usd` also from the machine's price table. A run whose contract declares one of them and has
nothing to count it with is refused, exit 125 `[budget-unmetered]`, with the cause and the fix: `capture: off`, a
machine `capture:` ceiling of `off`, no `models:` endpoint where the run captures with the forwarder (every
unprivileged run, tier `landlock`, and every `auto` contract under `record: off`), `record: off` under a contract
that pins `capture: uprobe`, or, for `cost_usd`, no price table at the
machine config's `prices:` path (or a table there that lists no model, or prices none: every entry lacks an input or
an output price). `tego rules check` reports the same contract
with a `[budget-unmetered]` warning that says the run is refused. Until 2026-10-16 such a run went ahead with only an `[unenforced]` compile warning and a
`budget-unmetered` gap, so an unattended night ran with a limit that did nothing. A budget a machine `limits:` ceiling
alone imposes is not refused: the run records `gap what=record why=budget-unmetered binary=<budget>`.
For an unattended run, declare the model endpoint under `models:` and install a
price table before relying on `cost_usd` (next section).

**Which model APIs a token or cost budget counts.** A budget counts the usage an answer states, in the shapes Tego reads, and
which shape an endpoint speaks is what its `models:` entry's `provider` says, never a guess from the answer: Anthropic's
Messages API (`provider: anthropic`; also its OpenAI-shaped chat completions endpoint on that host), and OpenAI's Chat
Completions (`POST /v1/chat/completions`) and Responses (`POST /v1/responses`) APIs (`provider: openai`, on the host the
entry declares: OpenAI's, a gateway's or a local server's that speaks those paths). For an OpenAI-style answer the tokens
counted are the prompt tokens minus the cached ones, plus the completion (or output) tokens, reasoning tokens included in
them; the cached tokens are the cache reads, priced at the table's `cache_read_per_mtok` and not in `tokens`. Tego never
changes a request, so a streamed chat completion is counted only when the client asked the API to state usage in the stream
(`stream_options: {"include_usage": true}`); a streamed one without it, a Responses stream without a completed event, an
answer past the capture cap (8 MiB), an answer cut short (the client or the agent closed the connection: a cancelled or interrupted stream), a Responses answer stopped by `max_output_tokens` (`response.incomplete`), another path of the API (embeddings, a stored response's retrieval) and an API of
any other provider spend tokens no budget can count, and a budget that cannot be counted is never silently ignored, so the
run ends at that answer: reason `error`, exit 125, run_end's detail "capture: 1 model exchanges spent tokens no budget could count (POST /v1/chat/completions:
usage unreadable); a token or cost budget cannot be enforced". `tego run`'s closing lines say it in words (the request, that its
usage could not be read, and that the fix is to remove `limits.tokens` and `limits.cost_usd` or to use a model API whose usage
Tego reads; for a stream with no usage it names the client option above), and `tego rules check` warns `[budget-uncounted]`
for a contract that sets one of the two beside a `models:` entry whose provider is not a counted one. The warning is not a
refusal, and it names the entry's line. `limits.repeats` does not count the tool calls of an OpenAI-style answer (not derived
yet). OpenAI-style counting is tested against a stand-in written from the provider's reference; the guest run with a real client is still owed.

Under `record: off` the uprobes place no probe, so an `auto` contract captures with the forwarder at every tier, and
its run refuses a direct connection to a `models:` host (`rule: models[<host>:<port>]`), as a tier `landlock` run
does: the agent reaches its model through the forwarder's base URL (`ANTHROPIC_BASE_URL` and its peers). An agent
that ignores that variable fails to reach its model rather than spend past its budget unseen. At tiers `cgroup` and
`bpflsm` under `record: summary` or `full`, a run with a model budget whose probes could not start (a capture object
the kernel refused, a spent `bpf.ring_budget`) is refused `[capture-unavailable]` even though the forwarder runs,
since that table does not refuse a direct connection; `capture: forwarder` is the fix that needs no probe.

An explicit `capture: uprobe` at either root tier with recording enabled is refused at start if the capture
programs cannot start, even without a model budget. Each probe now attempts a failed tail call into an empty
array to avoid a shared private stack on exposed kernels. The loader reads back the loaded instructions and
requires that call. If it cannot read them or the call is missing, the refusal and `tego machine check` say why. Auto
keeps the forwarder available, with the budget checks above. This does not remove the other documented capture
losses. All eight x86-64 kernel rows passed loading, read-back and availability with a disclosed dump-only test
overlay; the corrected stock check's RHEL 9 and Fedora 7.2 reruns and arm64 acceptance remain owed in a guest.
The Fedora 7.0 BPF-runtime comparison places the extra call's cost within noise, not zero (ADR 0150).

Host hardening can hide the instructions even after a successful load. Measured on Fedora 7.0.14, read-back worked
with `net.core.bpf_jit_harden=0` and `kernel.kptr_restrict=1`; setting both to 2 withheld read-back even from root.
All eight bodies loaded, but the visibility check made uprobe capture unavailable. The error says
`cannot verify capture stack safety: read translated instructions: instructions: restricted by kernel.kptr_restrict
and/or net.core.bpf_jit_harden sysctls`. Doctor still offered the bpflsm tier with 27 of 27 required hooks; its
capture summary said `0 of 6 programs load`, attachment not tested. That count describes availability after
read-back, not a verifier rejection.

Explicit `capture: uprobe` with `record: full` then exited 125 before the agent started, naming the cause and offering
`capture: forwarder` with a `models:` endpoint. Raising `bpf.ring_budget` does not remedy this read-back restriction,
although the generic refusal also mentions ring-budget remedies. With a declared endpoint and no model budget,
`capture: auto` started the forwarder, exited zero and recorded one count-zero `capture/mechanism-unavailable` gap
for uprobe. That observation does not establish capture of direct traffic bypassing the forwarder or every budget
and network-policy combination; the budget checks above still apply.

Keep the hardening settings and use `capture: forwarder` with a declared `models:` endpoint, or relax the blocking
setting only if the host owner accepts the tradeoff. Tego respects host hardening and never works around it.
JIT blinding combined with denied pointer visibility can also hide the stream, including missing `CAP_SYSLOG` with
`kernel.kptr_restrict=1`; that combination was reviewed, not measured here. `kptr_restrict` alone does not imply
failure for an unblinded program. Missing BPF privileges, denied program-info access, decoding errors or an actual
lockdown/LSM denial also make the check unavailable; no separate blanket lockdown refusal is assumed.

## Crash and cleanup
- The supervisor holds `runs/<id>/lock` with `flock(LOCK_EX)` for the run; the kernel releases it when the holder
  dies, so "live" is "lock held", with no pid file and no state file. `tego run`, `tego session stop` and `tego gc` sweep:
  for a run with `run_start` and no `run_end` whose lock is free, take the lock, write `1` to `cgroup.kill` if
  `cgroup.events` says populated, append `run_end reason=orphaned`, remove the cgroup directory and
  `$XDG_RUNTIME_DIR/tego/<run>/`. `tego status` never writes: it shows `lost`.
- If the supervisor dies, the agent's main process is killed by `PDEATHSIG`; descendants keep the inherited filter and,
  with the listener closed, every notified syscall fails with `ENOSYS` while Landlock and cgroup limits persist. This is
  fail-closed by design; the sweep collects the tree.
- Programs, maps and links are pinned under `/sys/fs/bpf/tego/<bpf_hash>/` (tier 2) and, for the decision plane, under
  `/sys/fs/bpf/tego/<bpf_hash>-<mode>/` (`lsm` or `fmod_ret`; see "Tier 3 and the decision plane"); the build lock is
  `/run/tego/bpf-<bpf_hash>.lock` (root 0700 only; there is no non-root `tegod`, ADR 0042), held `LOCK_SH` by every launcher
  of that build; the last one out takes `LOCK_EX|LOCK_NB`. It does not detach (ADR 0022): it stamps the lock's mtime
  and starts the build's timer (`tego __bpf-linger`, one per build), which removes the build once it has been idle
  for `bpf.linger` (default 5m, `/etc/tego/config.yaml` only), no launcher holds its lock, and its run set names no
  live cgroup. A timer that was killed is started again by the next run of any build once its build is past the
  linger (the timer then removes it, not the run), and by any root `tego session stop`. A root `tego gc` sweeps the same
  way; `tego gc --builds` removes every idle build at once. A removal returns only once the kernel has released the
  build's links (it waits at most 30 s for a program something else still holds), so `gc --builds` and a
  `bpf.linger: 0` run's exit take the kernel's teardown, a few seconds for a build with a plane, and the next run's
  load does not wait for it. A lock cannot go stale. `sudo "$(command -v tego)" machine check` lists every build (`--json`'s `builds`):
  whether a run holds it, how long it has been idle, whether its timer runs (`timer`, `timer_pid`) and so when it
  goes, the memory its programs and maps charge (`memlock_bytes`, the fdinfo `memlock` bpftool shows, each object
  once; `memlock_unreported` counts what the kernel did not report, shown as `n/a`, never 0; the run rings are
  `ring_bytes`), and why a build no launcher holds is kept, inside its linger or past it (`kept`): a run it enforces
  is alive, or its run set cannot be read (`kept_cause` says what the read met, for example a map of another layout
  pinned under its name). `gc --builds` removes neither of those; the first goes once its run's cgroup is gone, the
  second needs root to look at the pins machine check names and remove the build by hand once no run of it lives.
- The ledger is append-only and torn-line tolerant; nothing to repair.
- **Modes an agent took** (2026-11-02). An agent runs as the user who owns `~/.tego` (the config layer, `chain.log`,
  `tego.log` and the default ledger root in it), the ledger root, `$XDG_RUNTIME_DIR/tego` and its own run directory,
  and no Landlock ABI has a chmod right, so it can `chmod 000` them. `tego run` gives the owner back their rights on
  `~/.tego`, `config.yaml` and `tego.log` before it reads the config, and on `chain.log`, the ledger root, `.live` and
  `$XDG_RUNTIME_DIR/tego` before it compiles, warning `[own-state-mode]` for each; every run gives all of these back
  at its end too, and its own run and runtime directories. `tego gc` gives back `~/.tego`, `config.yaml` and
  `tego.log` before it reads the config too. If a layer is still unreadable or unsafe, gc reports
  baseline UNKNOWN and the cause, returns 125 and sweeps/deletes nothing; the daily unit's journal
  carries the warning. Only the owner's bits are added,
  since someone else could have changed what a directory others can write holds: a `~/.tego` or `config.yaml` made
  group- or other-writable still has every run refused by the config trust check, with its fix (`chmod g-w,o-w`), and
  a `$XDG_RUNTIME_DIR/tego` made so has every run that routes Codex refused, with its own fix (remove it, or export
  `XDG_RUNTIME_DIR` as an absolute directory only you can write), while the other runs go on without a runtime
  directory, so with no `TEGO_REASON` (`tego.log` says why). Each restored mode is a `gap what=record
  why=own-state-mode-restored` naming the path in the run's ledger, which the receipt and `tego status` count as no
  lost action. A root launcher restores none (it reads and writes through any mode); its agent can take the modes of
  your own state above, which your next unprivileged `tego run` restores, so if you launch only as root, restore them
  by hand for your own `tego status`, `events` and dashboard. Restore by hand too a link at one of these names (left
  alone), the directory of a run another user owns, `$XDG_RUNTIME_DIR` itself (at mode
  0 every later run is refused `[run]`: no runtime directory can be made in it), a directory inside a run's runtime
  directory (its `CODEX_HOME`), which otherwise keeps that runtime directory, `auth.json` included, until you log out,
  and the files you write that tego only reads (a `$TEGO_CONFIG` outside `~/.tego`, `prices.yaml`, the profiles and
  the registry): `chmod 700` a directory, `chmod 600` a file. The run directories of your live, orphaned and earlier
  runs (each with its `events.jsonl`, lock file and `blobs/`) are given back by your next `tego run` at its start and by
  `tego gc` (not `--dry-run`), owner bits only. While a run lives, its agent can still take the modes of
  its own run directory, which keeps `tego status`, `events` and `stop` out of it until the next restore: they say the path, its mode
  and the one command, `chmod -R u+rwX '<run directory>'`, which adds your own rights only; or stop such a run
  with Ctrl-C in its terminal or a signal to its launcher. A bad config layer alone does not block those
  observation/stop commands: they report a degraded load with baseline UNKNOWN and the cause.
  Compile, check, launch and rule-decision commands refuse the bad layer. Doctor reports its mode
  problem and repair advice but restores nothing. The decision planes can hold chmod under their
  applicable deny-write rows; Landlock and fanotify cannot. See ADR 0144's per-mechanism limits.
- **Another manager's cgroup programs.** A program attached to a cgroup at or above the runs' without
  `BPF_F_ALLOW_MULTI` (`bpftool cgroup attach`'s default) refuses every run's program of that attach type: a root run
  stops before the agent starts (exit 125, `ErrCgroupAttachConflict`), and `sudo "$(command -v tego)" machine check` fails the same program's
  row first. Both name the cause and `bpftool cgroup tree`, which shows the holder; detach it, or attach it again with
  `BPF_F_ALLOW_MULTI`. systemd attaches its own programs that way, so they do not conflict.

## Tier 3 and the decision plane
Tier 3 (`bpflsm`) is the kernel decision plane in LSM mode, on top of tier 2 (ADR 0024).
The same programs also load as `fmod_ret` hooks, which is how tier 2 decides opens, execs and file mutations in the
kernel where `bpf` is not an active LSM. `sudo "$(command -v tego)" machine check` says which it is:
`decision plane: fmod_ret (tier 2 decides opens in the kernel; tier 3 needs bpf in lsm=); build 1a2b3c4d, ...`. The
build is the first 8 characters of the binary's object hash, the name of its pin directory. Where `bpf` is already
in `lsm=`, fmod_ret is the pin's doing (`bpf.plane pins fmod_ret`) or LSM mode's failed probe (`tier 3 needs LSM mode
to pass, see the lsm mode line`, whose detail and fix say why); editing `lsm=` fixes neither.

- **LSM mode by distribution.** `bpf` is already in the boot `lsm=` list on Debian 13, Fedora, RHEL 9 and 10 and
  Amazon Linux 2023: with the other root-tier preconditions, tier 3 needs no LSM change there. Ubuntu
  (24.04, 25.10, 26.04) lacks it. WSL must first satisfy the initial process-id namespace requirement; the measured
  WSL 3.0.5 guest does not. Changing its LSM list cannot make root tiers available.
  Doctor's `lsm` line then fails for tier 3 only (tiers 1 and 2 are not affected) and prints one fix built from the live
  list, so no LSM the machine runs is dropped: `update-grub` after editing `GRUB_CMDLINE_LINUX_DEFAULT` in
  `/etc/default/grub` on Debian and Ubuntu, `grubby --update-kernel=ALL --args="lsm=..."` on the RHEL family, Fedora and
  Amazon Linux 2023; then reboot. An Ubuntu cloud image sets that variable again in
  `/etc/default/grub.d/50-cloudimg-settings.cfg`, so there the line goes in a later file in that folder. `tego run --tier bpflsm` without LSM mode is refused with that line, never run at
  another tier.
- **`fmod_ret` and its residual.** Without `bpf` in `lsm=`, tier 2 runs the plane as `fmod_ret` hooks on the `security_*`
  functions. A refusal there skips the other LSMs' hooks for that access, so AppArmor's own check and its audit record
  of that access do not happen. A kernel built with Clang LTO, which can inline a `security_` function at a call site,
  has no `fmod_ret` mode. Nor has a kernel not proven never to preempt kernel code (ADR 0024 (16)): under full, lazy
  or RT preemption the kernel skips an `fmod_ret` program on a CPU where a preempted task is still inside it, and the
  hook goes on undecided, so machine check rules the mode out and its line names the model it read (`preemption lazy, from
  /sys/kernel/debug/sched/preempt`) or what it could not read. That is every x86_64 and arm64 kernel from 7.0, which
  offer only full and lazy preemption; a 6.x kernel whose preemption is none or voluntary (Ubuntu's 6.17 by default,
  measured) keeps the mode where machine check can read its live mode in debugfs (a dynamic build; lockdown can refuse that
  file, and then the mode is refused too), and a `preempt=full` or `preempt=lazy` boot line takes it away. Such a machine needs `bpf` in `lsm=` for a plane mode (LSM programs are never skipped this way), else tier 2
  decides on the fanotify fallback.
- **`bpf.plane`** (`auto`, `lsm`, `fmod_ret`) is honoured from `/etc/tego/config.yaml` only, like `bpf.linger`: a
  user's layer that sets it gets a warning and changes nothing. `auto` takes the best mode that passed machine check's probe,
  `lsm` before `fmod_ret`, else the fanotify fallback. A pin to a mode that did not pass falls back to fanotify at tier
  2, said so on machine check's line; tier 3 never falls back.
- **Pin layout and gc.** A plane mode's programs, maps, links and fill filler live in
  `/sys/fs/bpf/tego/<bpf_hash>-<mode>/`, next to the build's own `<bpf_hash>/`, where `<bpf_hash>` is 16 hex characters.
  They are removed with the build: idle for `bpf.linger`, or now with `sudo "$(command -v tego)" gc --builds`. A build is never removed
  while a live run's row names it.
- **Row caps.** A run's contract becomes rows the kernel walks: at most 4096 file rows (one per keyed inode) and 1024
  exec-map entries (the exec entries, the bare names and one policy row) a run. A contract over either cap is never
  truncated, since a row left out is a rule the kernel does not apply: `tego rules check` reports `[unenforced]` naming
  `bpflsm`, as an error when the contract compiled to tier 3 and as a warning when an `auto` run may land there, and
  the run is refused at Prepare. The fix is narrower `fs`, `deny_read` and `exec.allow` entries (one entry per directory
  rather than per file), or `tier: cgroup`. The built-in `.env` scan can name up to 50,000 files. Since 2026-10-27
  (ADR 0043) a table past 1,024 keyed paths drops the per-file rows of covered files beneath a write entry, which its
  name entries refuse by name (`tego rules check` prints the compaction line), so a project with 4,500 such `.env` files
  stays at tier bpflsm; files that are not beneath a write entry, or have a second link, keep their rows. Name entries
  have their own caps a run: 64 entries and 64 name rows, 8 scope directories, 4 prefix lengths and 8 leads (a name's
  first eight bytes); an entry past one keeps its compile-time expansion only, which `tego rules check` reports
  `[unenforced]`, and the run's `fs.deny_read.created_later` is then false.
- **Lockdown.** Under `lockdown=confidentiality` the kernel refuses the probe-read build, so only the build that reads
  through `bpf_rdonly_cast` loads: Ubuntu 24.04 and later, Debian, Fedora and RHEL 9.8 have it and load;
  Amazon Linux 2023's 6.1 has no `bpf_rdonly_cast`, so under confidentiality it has no plane mode and tier 2 decides by
  fanotify, and `--tier bpflsm` is refused. A kernel without `bpf_loop` (below 5.17 without a backport) also has none.
  Doctor's line names which condition rules the modes out.
- **Cost per open.** The plane's lookup costs about 0.2 µs an open, and LSM mode 25 to 72 ns more than `fmod_ret`. The
  budget kill test 4 holds tier 3 to, 2 µs an open, is for `record: summary`, the default. `record: full` adds the
  recorder's own cost on top, 65 to 110 µs an open in a 2026-09-30 review, which is the recorder's and not the plane's.
  While a build is attached, every open, exec, mmap and path operation on the host pays the lookup, and a host process
  is never decided. Every plane run carries the built-in `.env` name entries, so the figures above are with the name
  check on (2026-10-20, 6.17: kill test 4's excess 916 to 986 ns, Prepare's fill with 64 name rows 0.14 ms more); what
  the name check alone adds to an open (ADR 0043's 30 ns target, 1 µs for a refusal) is below what the guest perf
  suite resolves so far (enforce-plane §10.1 condition 7).
- **Cold attach.** The first run of a build attaches its programs, which holds the kernel's ftrace locks for about 1.7 to
  3.7 s depending on the kernel; removal costs the same. Linger (`bpf.linger`, default 5 m) keeps the build attached
  after the last run, so a run soon after another pays 136 to 204 ms, not the attach.
- **What tier 3 does not decide.** Bytes read through a descriptor the run received from outside it (no
  `file_permission` hook), anonymous executable memory, code mapped from a readable file outside every write entry that
  was never modified, and an interpreter's own logic. It does not touch a process outside the run, and root can list and
  remove the programs.

## Sizing the ring budget
Each tier-2 run gets its own ring buffers (ADR 0026): a record ring, and a capture ring when it captures with
uprobes, each `record.ringbuf` bytes (default 2 MiB; a `record: off` run's record ring is a fixed 256 KiB). A ring
charges its size plus its page array in memlock: about 2.1 MB for a 2 MiB ring (an 8 MiB ring charges 8,433,944 B),
so about 4.2 MB for a run that captures. `bpf.ring_budget` (default 256 MiB) caps what every live ring of every build
on the host charges together, about 60 capturing runs at the default size. A run whose record ring would pass it is
refused, exit 125, naming the budget; one whose capture ring would pass it runs without capture, and is refused
`[capture-unavailable]` when it has a `tokens`, `cost_usd` or `repeats` budget, or explicitly requests uprobe capture with recording enabled. `sudo "$(command -v tego)" machine check` shows, in its
tier-2 builds section, how many run rings there are and what they charge against the budget, per build and in all.
Raise `bpf.ring_budget` for more concurrent runs; raise `record.ringbuf` only if runs report `ringbuf-full` or
`ring-buffer-drop` gaps (the reader drains every 50 ms and is woken at an eighth full). A run that captures with uprobes needs
`record.ringbuf` of at least 128 KiB, the room for two of the largest capture chunk; below that it is refused, exit
125, naming the minimum. Both are honoured from
`/etc/tego/config.yaml` only: a user's layer that sets them gets a warning and changes nothing. A launcher killed
before its teardown leaves its rings charged until its build's next run reclaims them.

## Multi-call programs in `exec.allow` (2026-11-11)
On Ubuntu 25.10 and later, `ls`, `cat`, `sleep`, `env` and about 110 more commands are one program file, uutils
coreutils, hard-linked under each name (115 links on 25.10 and 116 on 26.04.1, measured). On a busybox host each
command is usually a symlink to one file. Such a program picks what it does from the name it runs under, so an
`exec.allow` entry for one name can admit more than that name:

| The host's layout | Tier landlock | Tiers cgroup and bpflsm (root) |
|---|---|---|
| Names that are hard links of one file (uutils coreutils) | the listed names; an agent that wins the exec race can run the file by any of its names, `/usr/bin/coreutils rm` among them | the listed names only |
| Names that are symlinks to one file (busybox) | every applet | every applet |
| A build that runs the program `argv[0]` names (busybox; upstream uutils through `/proc/self/fd`) | any applet through a listed name | the same |

Ubuntu's own coreutils build refuses a name that does not match the file it runs as, and with only `/bin/sh` and
`/bin/ls` allowed none of the 11 name forms of the `ls` link tried made it act as `rm` on Ubuntu 26.04.1. Upstream
uutils has no such check. `docs/GAPS.md` C63 says what was measured and what is not known, and SEMANTICS §4 states
the rule. Since the same day an `exec.deny` or `exec.ask` entry also meets the names upstream uutils picks a utility
by on such a file (`xrm`, `myutils rm`), even for an exec an `exec.allow` entry admits (ADR 0048's amendment of
2026-11-11); an `exec.allow` entry does not read them.

`tego rules check` notes each such file once, at the first entry that leads to it, with the entries that share it and
its link count:

```
warning: agent.yaml:8:7: the exec entries "ls" and "cat" lead to one program file, /usr/lib/cargo/bin/coreutils/ls, with 116 names (hard links). Tiers cgroup and bpflsm admit only the names listed; tier landlock admits the file by any of its names to an agent that wins the exec race, and a multi-call build that reads argv[0] (busybox, uutils without Ubuntu's patch) runs any program it holds through a listed name [exec-multicall]
  fix: list such a file only where every program it holds may run; docs/GAPS.md says what each tier and each coreutils build admits
```

Where one of those entries names the file's dispatcher (`/usr/bin/coreutils`, `busybox`), in any order, the note
names that file instead and says it runs the program `argv[0]` or `argv[1]` names at every tier.

It is a note: it changes no rule and no exit code, and `tego run` prints it only with `-v`, since on such a host nearly
every coreutils entry has one. The dashboard's contract check shows it as `tego rules check` does. `tego machine check` prints a
`multicall` line when the file behind `ls` has more than one link or is busybox, toybox or coreutils; it reads the
file's link count and name and runs nothing. List a multi-call file only where every program it holds may run. Where
the name must bound the program, run at tier cgroup or bpflsm, which needs root. `exec.deny` command rules read
`coreutils rm` and `busybox rm` (ADR 0048), but not every name form upstream uutils accepts.

`tego machine check` also prints a `note routing:` line (and `--json` a `routing` key) when a routing table holds `local`,
`broadcast` or `anycast` routes that Tego does not read as this host's: a table that no policy rule the run's own traffic
can match leads to (Cilium's `local default dev lo table 2004` behind a mark), named by number. It reads the
policy rules and routes as a run does, unprivileged, and runs nothing. The same line says so when the rules cannot be read.
Net rules for this host then do not cover a destination only those routes deliver here (GAPS C46).

## Exec command rules
`exec.deny`, `exec.ask` and words after a command in `exec.allow` name what a program is asked to do: a whole
command, a subcommand, or an option set ([ADR 0048](../adr/0048-exec-command-rules.md); the per-tool rows are in
`docs/spec/exec-command-rows.md`). `tego rules check` prints each entry's exact reading, the row that read it and what
it also matches; `tego rules check c.yaml --exec 'git -C . push'` shows how one command line is decided in every tier. `rules check` is a
static preview: the run is authoritative and fails closed, so `rules check` may print `allow` where the run refuses on a
fact it does not read — a `#!` interpreter that is missing or unreadable, an execute-only image, a dynamic loader's
program given by a bare name or reached through a symlink, a second `#!` stage, or the file-identity interpretation
(a renamed or hard-linked tool). `rules check` never refuses what the run allows.

Compile warns when a command entry uses more than two leading option dashes or one dash before a long option
name where the tool does not accept that spelling. Tool-defined single-dash long options and short words do not
warn, including `go build -race` and `go test -run Test`. Tools without a known row retain literal option words,
including `find -name file` and `java -jar app.jar`. The warning names the entry and the ordinary spelling it
probably meant. Use that spelling now; a later minor version will reject warned entries. For compatibility, an
extra-dash deny or ask entry keeps every match of the released build and also matches its literal spelling. An
allow entry uses only the literal spelling, and an unknown allow option is invalid for a tool with a known row.

| Recipe | Contract | What it does not cover |
|---|---|---|
| Never push | `exec: {deny: [git push]}` | `git send-pack`, `git http-push`, a git library in the agent's own code, `curl` to the server: bound those with `net` rules to the remote |
| No recursive deletes | `exec: {deny: [rm -r]}` | `find -delete`, `rm` on each file, a script's own unlink: bound them with `fs.write`. Deny `rm -r`, not `rm -rf`: without a tty plain `rm -r` removes the same tree |
| No publish | `exec: {deny: [npm publish, pnpm publish, yarn publish, yarn npm publish, cargo publish, twine upload]}` | a registry write over `curl`; bound it with `net` rules to the registry |
| Read-only git | `extends: base/read-only-git` (examples/profiles) | `git config <key> <value>` and `git branch <name>`, which write by operand count; the built-in `deny_write` set refuses writes to `.git/config` and `.git/hooks`, and the `fs` rules the rest of `.git` |

A deny entry wins over every allow entry, at any specificity; there is no exception syntax. `exec: {deny: [...]}`
with no `allow` key is a deny-list: images stay unrestricted. `exec.ask` is reserved and refuses every match.
Running the dynamic loader directly, `ld-linux-x86-64.so.2 /usr/bin/rm -rf tree`, is decided on the program it loads
(`command_via: loader`); an operand the supervisor cannot read as the loader will, such as a bare name the loader
would search library paths for, is refused `loader-unresolved`, and in a run whose images are restricted the program
must be granted like any image (`loader-program-unmatched`). In a deny-list run, a linked file in the run's own
generated `CODEX_HOME`, run by its path or through a descriptor, directly or through the loader, is refused
`codex-home-exec`: the run grants that directory for writing, and a copy of a denied program written there would
otherwise run under another name. The run's `hook-state` directory, which a harness provision adds,
is held the same way, refused `harness-state-exec` (added 2026-10-24). It is judged where the kernel says the file lies, so a directory there that the
agent makes unsearchable does not hide one (amended 2026-10-17). A copy there that the agent opens, unlinks and runs
through its descriptor runs fileless, as a memfd copy does (R2 below). Under an allow-list contract the run admits
the harness hook a provision names with its exact argv and nothing else (added 2026-10-25, ADR 0064):
`exec.harness-hook[<tego binary>]` in `run_start.runtime_grants`; any other `tego` command the agent runs is refused
under that rule, exit 126. Compile refuses an `fs.write` entry or `fs.ask` scope at or over the tego binary, the
`tego-control` beside it, the ones PATH finds, and any `tego` or `tego-control` in `~/.local/bin`, `/usr/local/bin`,
`/usr/bin` or `/opt/tego/bin`. Alias and overlay layer comparisons follow exactly the
[compile-time mount boundary](../adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary), including
its refusal of grants affected by ambiguous visibility, unreadable identity or an unplaced protected place. The
message names the mount point or path. Same-point stacking uses parent relationships and supported live checks,
never printed row order. A malformed, unreadable or over-bound mount table refuses every write and ask grant.
A tego binary with a second hard link refuses every write entry on its filesystem, unless only root may write the
file and the agent is not root; install a fresh copy with one name outside every write entry and run that one.
Identified kernel interface filesystems (cgroup, bpf, proc, sysfs, mqueue, resctrl and the others ADR 0059 lists;
devpts allowed only at `/dev/pts`) refuse grants that reach them. Unreadable running, PATH or standard-install binary
candidates also refuse, with their cause. Closure bounds refuse grants.
Absent binary layers (ENOENT or ENOTDIR), relative overlay layers and unnamed FUSE, eCryptfs, aufs or shiftfs backing
alone refuse no grant. Tego never guesses the base folder of a relative layer; absolute layers of the same overlay
and every visible binary name remain protected. When a FUSE or eCryptfs filesystem holds any protected regular
file, its existing absolute source directory joins the protected closure with visible aliases; entries at, over or
inside it refuse. Relative, missing or non-directory sources remain unplaced. Source text does not clear FUSE or
eCryptfs warnings: FUSE's mounter chooses it, and live eCryptfs lower-directory identity is not established.
Merged root ownership gives no exemption or assurance. With any of these backing limits, compile emits one
`overlay-backing-unknown` warning per write or ask entry that covers, or lies
under, another visible storage mount. The new unplaced classes exclude only their own filesystem device; another
protected filesystem's device can still hold their backing folders. All cases exclude kernel interfaces and memory
directory storage; regular-file binds established by live checks can still warn on memory filesystems;
the absent-only rule also excludes discovered binary overlay devices. Runtime storage or a backing folder on a
memory filesystem also mounted at a writable directory gives no warning (GAPS C65). A single-file mount is exempt
only for absent or relative overlay backing, after live snapshot-bound mount ID, type and size checks and
comparison with every affected protected regular file. A nonempty byte-identical alias refuses, executable or not.
Two empty files prove neither identity nor difference and warn without a byte-alias refusal. FUSE/eCryptfs file binds
never get this exemption: their stored bytes can differ from the visible bytes. Unreadable protected files and
unidentified or changed mount points give no file-bind exemption. The warning names the grant, mount and any protected
file itself directly on unnamed backing. This includes a contract on sshfs or a config layer, even with Tego on ext4. Keep runtime
storage and the whole host filesystem out of writable places. For unnamed backing, keep the folder storing
encrypted or mirrored files out of every write grant: Tego cannot tell whether such a mount shows protected storage.
The warning explains the missing relative base or names the filesystem whose backing folder is unknown. With no
storage mount meeting a grant there is no backing warning; a separate mount advisory may still print.
Runtime tables now replay 2026-11-12 Docker 29.1.3, containerd 2.2.1 and rootless Podman 4.9.3 captures
(kernel 6.8.0-147-generic); current-head container execution checks are
owed in a guest. docs/site/built-in-refusals.md lists what is always refused. A tego installed anywhere else is held only when it is the
one running (`tego run` checks again with its own file). Keep the binary outside them by its other names too (no
bind mount of its directory into one), and give it one link, or the run drops the provision (`harness-hook-writable`)
and the agent learns of refusals through `TEGO_REASON` only. Keep it off a filesystem whose layers, image or device
lie under such an entry too: an overlay's layers, a loop device's backing file and an image the filesystem is mounted
from are checked, and unplaced backing drops the provision (ADR 0064 D2, amended 2026-10-25).
This warns and the ordinary run continues; the hook scan does not share contract compile's backing-warning guarantee.
The real `Run` test reaches that scan through the product provisioner for Claude Code and auto on captured
relative-overlay and FUSE-root tables. Other product harness kinds have no hook provision and skip that scan.
Kernel execution is owed in a guest.
A layer reached only by another spelling than the overlay's options give (container storage bind-mounted in elsewhere), a second mount of one
network export, and a host share's other names are not seen, so do not place the binary there. A multicall binary that re-dispatches to itself past
the matcher's depth bound (`busybox busybox busybox busybox busybox rm -r`) is refused `command-unresolved` rather
than allowed, since the applet it finally runs could be a denied one; so is an exec whose reading yields more
interpretations than the matcher keeps (32 per exec).

**Residuals, stated plainly** (ADR 0048's R1–R13). Command rules are launch rules: they see execs, not effects.
- R1: a program that does the work in process (a git library, Python or Node code, bash loadable builtins, busybox
  `sh` applets) or talks to the service directly (`curl` to the registry) is no exec of the named command. The
  boundary for effects is the `fs` and `net` rules.
- R2: a copy of a binary under another name is matched by its names; identity covers links and bind mounts of
  one-link binaries only. In deny-list mode beside `fs.write` the agent can copy git and run it, and `rules check` warns
  (`exec-rule-coverage`); restrict images with `exec.allow` to close it. Without a write entry it can still run a
  copy from a memfd or from a deleted file (one written into the run's `CODEX_HOME`, opened, unlinked and run
  through its descriptor: `codex-home-exec` refuses only a file still linked there), recorded `allow` unmatched
  with `fileless`, and map a program's file into its own process, so `rules check` warns on every deny-list (amended
  2026-10-16). A deny entry refuses a command, never the program's code.
- R3: rewriting from outside argv is not read: cargo, gh and aws config aliases, kubectl `kuberc` aliases, and
  environment that changes parsing (`POSIXLY_CORRECT`, `GIT_CONFIG_PARAMETERS`, `NPM_CONFIG_*`). git aliases re-exec
  and are seen; git's autocorrection is read.
- R4: rows are versioned data; a tool release can add an option, an alias or a helper. Unknown options fail closed
  for deny entries; a new helper is refused until its row lists it.
- R5: at tier 1 and the fanotify fallback an allow is the supervisor's copy of argv, and a sibling thread can rewrite
  argv before the kernel copies it again (`TestIntegrationExecRuleRaceTier1` measures it); the cell
  `exec.rules/argv` is in `run_start.best_effort`. A refusal is exact.
- R6: at the plane tiers the kernel holds a pinned run's execs to the decided facts (ADR 0048 P2) only where the
  plane's mode passed machine check's exec pin cell (`plane.exec_pin`); elsewhere, and for a run Prepare could not pin,
  they are R5's case too, and `exec.assurance: kernel` refuses such a run.
- R7: an exec whose verdict depends on argv past 8192 arguments or 128 KiB is refused, naming the bound.
- R8: the gate's `exec matches` reads names and argv only.
- R9: interpreter dispatch covers the named entry points (`python -m pip`, `node npm-cli.js`); code given with
  `-c` or `-e` is not a command.
- R10: options an allow entry does not name are free: `git push origin feature/*` allows `--force`; deny the option.
- R11: an allowed entry's helper closure admits direct use: under `allow: [git fetch]` the agent can run
  `git rev-list` itself; compile prints each entry's closure.
- R12: documented rows are not checked against a binary; compile prints probed or documented on each line.
- R13: an image whose first bytes the supervisor cannot read is refused (`image-unreadable`): its `#!` line could
  name any ruled tool. At tier 1 that means every execute-only file the user cannot read (RHEL's `sudo`, mode 4111).
  At the root tiers the supervisor reads as root, which reads every local file. On an NFS export with `root_squash`
  root reads as the export's anonymous user, and a FUSE mount without `allow_other` or `allow_root` refuses root
  outright: in a run with command rules an image there that the supervisor cannot read or reach does not run
  (`EACCES`), even in a deny-list run. Mount it with `allow_root`, export it without `root_squash`, or run the tools
  from a local copy.
  The `#!` line of every other image is read, so `#!/usr/bin/rm -rf` is `rm -rf` to the rules.

**git's layout.** git re-executes itself and its helpers from its exec-path, which is another file than the `git` on
`PATH`: `/usr/lib/git-core` on Debian and Ubuntu, `/usr/libexec/git-core` on RHEL and a source build. An
`exec.allow` entry naming git grants that directory's `git` and the remote helpers its closure needs, derived from
where the resolved binary lies, and compile prints them.

## Completing the gate's opens in the run (`gate.completion: held`)
A gate's `fs.read` and `fs.write` rules score what the supervisor copied from the syscall, and by default
(`completion: copied`) an open they do not refuse is handed back to the kernel, which reads the pathname again: a
sibling thread that rewrites it in between opens what the gate never scored. That cell is listed in
`run_start.best_effort` as `gate.fs.read/open` and `gate.fs.write/open`. `gate.completion: held`
([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) Stage B) closes it: the run starts an open deputy
(`tego __open-deputy`, a process of the run with its Landlock domain, cgroup and credentials, under a seccomp
allowlist and not dumpable), every open of an fs kind the gate can score to `allow` or above (*amended 2026-10-20*, ADR 0007) is pinned by the deputy, decided
on the object pinned, opened by the deputy and delivered, and its ledger line says `gate_facts: held_object`.

```yaml
gate:
  completion: held
  rules:
    - 'fs.read matches "*.env"': 90
```

What it costs and what it leaves:
- Latency: a held open took 2–4× the copied path's median in the measurements (ADR 0041 §Performance, TARGET-MISS),
  which is why it is an opt-in. Only opens of a kind the gate can escalate are held. With TOMOYO active,
  the two bounded fact reads added about 26.50 microseconds per authority check in a Debian 13 guest
  benchmark of the shipped check (five 2-second samples; ADR 0041); end-to-end acceptance remains open.
- The run's processes cannot make Landlock domains of their own (`landlock_*` answer `ENOSYS`): an agent that
  sandboxes its tools with Landlock finds it unavailable. `tego rules check` says so in its gate line.
- A deputy that cannot start fails nothing: the run warns `[held-unavailable]`, decides those opens on copied facts,
  and `run_start.best_effort` keeps the open cells (run_start's `capabilities` row `gate.fs_open_completion` is
  false).
- **Host security authority (SEC08, amended 2026-11-17).** A held file open checks the requesting thread
  against the process opening the file, including before reads, creates, truncates, approvals and alternates.
  AppArmor needs equal full labels and proof that the reader is in the root policy namespace (readable
  `.ns_level` zero). Equal visible profiles in a child namespace can hide different ancestor restrictions.
  SELinux needs equal full contexts and, before potential file creation, equal readable `fscreate` contexts.
  Smack always refuses because the other thread's process rules cannot be queried. With TOMOYO active
  (including Debian's stock kernel), held opens require the checking thread's own domain to be `<kernel>` and
  the first policy-update line to equal the exact 49-byte never-updated kernel line, newline included. Both facts are read afresh; no policy observation is retained between checks or runs; no policy
  loader is needed on a stock Debian install with no policy. An observed domain other than `<kernel>` refuses held opens
  on this machine. If TOMOYO securityfs is unreadable, expose readable
  `/sys/kernel/security/tomoyo/self_domain` and `stat`. Under Docker's default AppArmor profile a bind at
  `/sys/kernel/security` stays unreadable (ADR 0041's round-three evidence), so bind the host's
  `/sys/kernel/security/tomoyo` read-only at another path (`-v /sys/kernel/security/tomoyo:/run/tego-tomoyo:ro`) and
  name it in `/etc/tego/config.yaml` as `tomoyo: {facts_dir: /run/tego-tomoyo}` (a clean absolute path; a user layer's
  value is ignored with a warning). Tego then reads `self_domain`, `stat` and `profile` there and accepts each only
  when it is on securityfs, on a read-only mount whose root is TOMOYO's own directory; a writable bind, another
  securityfs directory (`apparmor/`), a tmpfs copy or a path through a link refuses as before, and `tego machine check` names
  the path read. Each check reads `/proc/self/mountinfo` too, so a held open costs more there. A container that cannot
  be given the bind keeps refusing: there is no TOMOYO contract opt-in and no setting that assumes TOMOYO enforces
  nothing. A nonzero or timestamped
  update line says policy was updated since boot: every held file open on the machine is refused until
  the next restart, even without policy activation (GAPS C75). No host privilege is needed to cause
  this: TOMOYO's built-in initializer rules create a domain and count an update for a program named
  `/sbin/modprobe` or `/sbin/hotplug`. The name is the link's own path, without following the final
  link, from the root of the starting process's mount namespace. A container with a real `/sbin`
  directory, or a local user able to create a user and mount namespace with that layout, can move
  the counter for the whole machine. The refusal returns after a restart if such a program runs
  again. This fails closed: opens are refused, and nothing is opened that should not be. A root tier (cgroup or bpflsm,
  launched by root) recovers: its launcher can read TOMOYO's root-only `profile` and admits a held open when the whole
  profile, read between two reads of the update line, has no mode `enforcing` in any namespace, profile or category
  (ADR 0041 SEC08b); tier landlock's launcher is the invoking user, cannot read it, and keeps the refusal, whose words
  then add "a root tier can prove nothing is enforced, and this tier cannot read TOMOYO's profile". On Debian
  12 and 13, `/sbin` is a link into `/usr`, so the host's modprobe is named `/usr/sbin/modprobe` and
  does not match; the counter was measured at zero after boot and module load/unload. For a machine
  that does not use TOMOYO, the lasting remedy is to omit `tomoyo` from the boot `lsm=` list, retaining
  the other active modules: on Debian, edit the list in `GRUB_CMDLINE_LINUX_DEFAULT` in
  `/etc/default/grub`, run `update-grub`, and reboot. The warning and own log name TOMOYO and the failed fact;
  `tego machine check` reports the current observation. See the TOMOYO residual immediately below (also
  ADR 0041 and GAPS B14).

  What the TOMOYO check leaves:

  (a) A TOMOYO policy activated between an authority check and the open it admits is not noticed for that one open; this requires the machine's administrator to act in that interval. (b) A kernel compiled with its own TOMOYO policy and activation without a loader (`CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER`), or with a hand-made built-in policy that predefines its domains, can enforce with a counter that never moved; the shared running-kernel build-configuration reader refuses held opens when it positively reads `CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER=y`, while an unreadable configuration changes nothing, and none of the distribution kernels we tested does this (Debian 12 and Debian 13 configurations inspected). (c) A container that hides TOMOYO securityfs refuses held file opens (GAPS C74). (d) The counter can return to its never-updated reading only after its full range of counted updates with the clock set to the epoch, an administrator's deliberate act.

  Differences return
  `EACCES`, `held-label-differs`; unavailable authority facts return `held-label-unavailable` in the ledger,
  with the missing fact in the log and the `[held-label]` warning explaining the requirements.
  The active module list uses `lsm_list_modules(2)` on 6.8+ with securityfs fallback: hiding the securityfs list
  alone does not break matching-label opens when the syscall works and AppArmor depth remains visible.
  Hiding all securityfs on AppArmor also hides depth; proc labels cannot prove stack completeness, so those
  completions refuse by default even for identical visible profiles. A dynamic program under held reads can then fail
  loading libraries. Direct opens and `O_PATH` keep their existing behavior. Differently labelled tasks can
  lose otherwise permitted opens. No label adoption or per-file policy-equivalence query is implemented.
  **Container administrator opt-in:** first establish outside the container that the supervisor reads from the
  root AppArmor policy namespace (for example the host sees its complete label and namespace setup). If
  securityfs cannot be exposed readably, the top-level contract may set
  `fs.apparmor_assume_root_namespace: true` (default false). This accepts the risk that hidden ancestor
  restrictions differ; matching `docker-default` names or enforce mode alone is insufficient evidence. It
  substitutes only for an unreadable depth, never a known nonzero/malformed depth or other missing facts.
  The opt-in is refused in inherited profiles, hashed in the canonical contract, warned at compile/startup,
  and always listed as `apparmor/assumed-root-namespace` in `run_start.best_effort` when enabled. That list
  discloses that the option was enabled, not that every open needed the assertion. Leave it false when the
  administrator cannot establish the assertion or will not accept that residual. The default refusal warning
  names unreadable AppArmor namespace depth, `EACCES` / Permission denied, `held-label-unavailable`, the
  readable-securityfs fix, and this opt-in. An outer seccomp filter must still permit `lsm_list_modules`
  when securityfs cannot enumerate modules; the option never supplies a guessed module list. On a kernel before 6.8 (Debian 12's 6.1) there is no such call to permit, and under Docker's defaults the container's own `/sys` has no securityfs, so the kernel's two answers are both unavailable and, with no list handed in, every held open is refused (`held-label-unavailable`) whatever `tomoyo.facts_dir` or the AppArmor opt-in say: the list is read first. A list can be handed in with the machine setting `lsm.list_file` in `/etc/tego/config.yaml` (a clean absolute path; a user layer's value is ignored with a warning; no key supplies a list inline). It is asked only after the call and `/sys/kernel/security/lsm` both failed, and it is believed only as the host's securityfs `lsm` file bound read-only (`-v /sys/kernel/security/lsm:/run/tego-kernel-lsm:ro`, read-only mount, file exactly `/lsm` in its filesystem), or as the three-line file root wrote in this boot (the image's entrypoint writes `/run/tego-lsm/lsm-list`): owned by root, not writable by group or others, in directories only root can write, no link in the path, not on FUSE or a network filesystem, naming this boot's id, listing names the kernel prints with `capability` among them, and read for a task that is not root and holds none of `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER` or `CAP_SYS_ADMIN` in its permitted set; each check is repeated at every open. A list file never decides a tier, only held opens: a name missing from a wrong list would switch off that module's label comparison, so a file that fails a check is refused in words that say which. A refusal that remains is on purpose, since a list that cannot be read cannot be assumed to name no label-bearing module; the launch note and `tego doctor` say what each way answered (`lsm_list_modules(2)`, `/sys/kernel/security/lsm` and the list file) and what can be changed. [The container guide](../site/containers.md) has the measured table and the settings of the documented flow.
  Key/socket creation and other operations are outside this file-open check. Previous timing figures predate
  these checks; current performance acceptance remains open.
- Still copied: `O_PATH` opens (`gate.fs.read/o_path`), non-open changes (rename, unlink, chmod and the rest:
  `gate.fs.write/mutation`), and the completion of an `fs.ask` or `fs.ask_read` approval or an alternate, which the
  supervisor makes as the agent's credentials.
- Held opens answer as the agent's own opens would, errno for errno, except where they refuse more: a process that
  made itself not dumpable gets `EACCES` for relative names (the deputy cannot read its working directory); under Yama
  (`kernel.yama.ptrace_scope` 1, Ubuntu's default) an agent's open of its own `/proc/<pid>/mem` is `EACCES`; and an
  open without `O_DIRECTORY` of an idle automount point itself opens the empty autofs directory instead of mounting
  it. Under a read gate a file whose name was removed cannot be reopened for reading through `/proc/self/fd`.

## Directory moves and protected names (C55)

At tiers `cgroup` and `bpflsm`, a directory move that loses `deny_read` name protection is refused even
when both ends are writable and no secret exists in that directory. The built-in `.env` rule starts at the
contract directory and launch cwd. It stops below `.git`, `node_modules`, `vendor`, `target`, `.venv` and
`venv`. Declaring another directory in `fs.write` grants writes; it adds no scan or name scope.

For example, ordinary `pip install --target ./target` with staging in `./tmp`, a broad `fs.write: ["./"]`,
and the contract outside that write hits this limit at the root tiers. Pip may fall back to copying and exit 0;
its recorded rename refusals still mean it did not run without interference. This also occurred in v0.1.0.
Tier `landlock` allows those pip moves; it has no corresponding name-mutation floor (A11 below).

One working arrangement retains protection at both ends using the existing contract-directory and cwd roots.
From a project containing a read-only `agent.yaml` and writable `tmp/` and `target/`, pre-create both:

```sh
mkdir -p tmp target
```

Keep other required grants, and write entries relative to the **new launch cwd**, `target/`:

```yaml
fs:
  write: ["../tmp/", "./"]
exec:
  allow: ["python3", "../tmp/", "./"]
```

Then launch from target, with the contract outside the writable paths:

```sh
(cd target && tego run ../agent.yaml -- python3 -m pip install --target . example-package)
```

Set `env.set.TMPDIR` to the **absolute** path of the pre-created staging directory. Rebase other relative
contract entries for that cwd, or use absolute paths. The contract directory covers staging, while cwd covers
target. The matching directory exec grants preserve REFER rights for native modules; retain the programs your
workload needs. No secret waiver or `deny_read: []` is involved. This is the arrangement tested offline with
pip and pytest by KT4. `tego rules learn <run>` explains it after the built-in-name rename refusal and leaves refused
actions out of proposed allows. An alternative is to install under a name such as `site-packages`, within the
existing protection at both ends.

The limit remains for a broad parent alone, declarations alone, a further dependency boundary below either
root, and moves outside all scopes. Separate deny rows and REFER still apply. Root planes protect their inode
scopes; supervisor pathname checks have their existing race limits. At tier `landlock`, held reads protect
launch-pinned identities, but a future name-only match outside watched launch targets can be renamed, exchanged
or hard-linked into an uncovered place before a held read pins it (GAPS A11). Keep secrets outside writable
folders; this remedy for ordinary pip work does not close that separate residual.

## Names made after a run started beside a `deny_read` (2026-10-26)
At tier landlock an enforced `deny_read` is built from one listing, at launch, of each directory above the target:
every name there is granted, the directory itself only lists. A directory or file made in one of those directories
after the run started, and a listed file replaced by a new one (an editor's save by rename), are therefore unreadable
to the agent for the rest of the run, and so is everything beneath such a directory; a new file inside a directory
that existed at launch reads as usual, and `ls` of the new directory still works. With the built-in `~/.ssh` entry
`$HOME` is one of those directories: a top-level entry made in `$HOME` during a long run is unreadable to it.

The record says so: such a read or exec gets `EACCES` from the supervisor and a `refused` line, `read-denied`, rule
`deny-read-snapshot` (`tego events <run> --rule deny-read-snapshot`), where it said `allow` before 2026-10-26. A run
records it wherever it sees opens: `record: full`, held reads, an `fs.ask_read`, a read gate or `reason.reads: on`. Remedy: stop the run
and start it again, which lists the directories anew ; for a 24/7 agent, keep what it must read beneath a directory that exists before it
starts, or put the secret outside the trees the agent works in.

Which directories froze is said under every record mode (2026-11-11), so a refusal that `record: summary` leaves no
line for can still be explained. `tego rules check` prints a `note` line naming them, and `tego run` prints the same note
on stderr before the agent runs:

```text
note: tego run: deny_read lists /, /home, /home/alice once, at launch: a file or directory made directly in one of them during this run cannot be read until it ends (a new run lists them again) [deny-read-frozen]
```

The run's `run_start` records them as `deny_read_frozen` (`{"dirs": [...]}`; past 64 it names the 64 deepest and
counts the shallower rest in `omitted`; `tego events <run> --json | head -1`), and `tego session show` and the dashboard's
Receipt tab name them under Coverage ("Frozen at launch"). The note is printed at the start of every run whose
ruleset listed one, without `-v` too: it weakens no rule, but it tells a person before it happens that a name made there later will be unreadable. A record
from a tego before this change has no such field. The root tiers install the same tier-1 ruleset and their
`run_start` names its directories too; that has not been run in a guest yet (docs/GAPS.md A12).

## Live blocks: refuse something in a running run, now (`tego block`)

`tego block <run> exec|net|path|read|write <value>` refuses a program, a destination or a path in a run that is running, within
about a second, without touching its contract; `tego unblock <run> <kind> <value>` takes the block away again (refused, exit 1 `[governed]`, when
it runs inside a tego run: an agent cannot lift what governs it, ADR 0123; it also refuses inside a container with
its own cgroup namespace, where it cannot tell, as does a `tego rule` write that widens; run them from the host) and
`tego block --list <run> [--json]` shows the run's blocks (also for a run that has ended, where they are no longer
enforced). It is the terminal side of the dashboard's Block now: both write the same file in the run's directory
under the ledger root, which the agent cannot write, and the launcher records each change as a `gap` line
(`tego events <run> --kind gap`). An `exec` value is an absolute path, a directory ending in `/`, or a bare name
(`curl`). An absolute path is matched by name and by the identity of the file it leads to, so it refuses that file
under every name it has: a multi-call program (uutils' coreutils, busybox) is one file, and on a machine whose
`/bin/ls` is one, a block on `/bin/ls` refuses `cat`, `sleep` and every other applet too. `tego block` says so when
it places one ("Note: /bin/ls leads to …, one file with 115 names here …", from the file's link count, or a link
named otherwise that leads to it), names a few of the other names it refuses too, and gives the bare name, which is
matched by name only and refuses that name alone; the dashboard's Block now says so too. A block the dashboard places
from a rules change ("Also apply now" or Apply now, after a program is removed from `exec.allow`) is different: it
refuses what the run's contract grants under the removed entry, which is fixed when the run starts: the file at the
path the entry led to then, by that path, a symbolic link to it, or `/proc/self/fd/N` of a descriptor opened there. A
link under the entry moved later does not move the block. So removing `/bin/ls` leaves `/bin/sleep`, another hard
link of the same file, running where the new rules still allow it (`match: link` in the overlay, version 5; ADR 0124,
amended 2026-11-11). Where an entry the rules keep leads to the same file at the same path (busybox's links all lead
to `/bin/busybox`), the block refuses that file there for both entries, as the whole-file block did; the next run
would run it. A run whose launcher predates it (it makes no `live-link` file in the run directory) gets the
whole-file block. A tego older than this change cannot read a version 5 overlay: its `tego block`,
`tego block --list` and dashboard say the file is invalid ("damaged, or a newer Tego wrote it") and change nothing,
so use the newer tego on that run. When a block refuses
another name of its file, the refused line's rule names the blocked path and its `path` the one that ran; `tego run`'s
summary, `tego session show` and the dashboard's row say so: "/bin/sleep: refused, same program file as /bin/ls, which is
blocked". `tego block` also notes a bare name no folder of its own PATH holds (a
typo, or a program not installed here) and an absolute path that is no file here now; either block still refuses
the program if it appears. An `exec` value may also be a **command**: a bare program name and words, `tego block <run> exec "git push"` (one argument, quoted;
`'...'` or `"..."` keeps a word that holds a space). It refuses what the same text in `exec.deny` would refuse, decided by the
contract's own command matcher, so `git -C . push origin` and `git --git-dir=x push` are the command too, `git status`,
`git stash push` and another program's `push` still run, and a glob word (`npm install --global *`) matches as it does in a
contract. The program is named by its bare name, never a path (an absolute value with a space is still a program path, as
before: `/opt/My Tools/run`). While one stands, tego's supervisor decides every exec of the run itself, at every tier (the
kernel plane's own handover of execs is off), on the copy of argv it reads; like `exec.allow` words that is best effort: a
thread of the agent that rewrites its arguments after the check can still run the command, unless the run's kernel pins
execs (`plane.exec_pin`). Facts the matcher cannot read are refused as an `exec.deny` entry refuses them (`args-unreadable`,
`image-unreadable`). A run whose launcher made no `live-words` mark in its folder (an older tego, or a run still starting) is
refused in words (exit 1, `[launcher-too-old]`) and nothing is written, since the whole-program block would refuse more than
the command; a launcher older than this reads the version 6 overlay as an invalid file ("overlay version 6, want 1 to 5") and
keeps its last blocks. The dashboard's Rules page offers the command's block when you remove an `exec.allow` entry with words
(only if every other `exec.allow` entry of that program is provably disjoint from it: a program allowed bare, or an entry
that may still allow part of it, has the saved change for the next run instead, and the page says which entry) or add one to
`exec.deny` (always: a deny comes before any allow), and the command is not written with a path. Nothing about it is a rules-file key or a new record field: the
gap lines carry `kind: exec` and the words as `value`, and the refusals `live.block[exec:<words>]` (ADR 0171). A live block
for a pattern (`**/.env`) is not built.

A `net` value is `host[:port]`, an IP, a unix socket path or `@name`; a `path` value is an absolute path and
everything beneath it (a relative one is read against the working directory and printed as the absolute path), for
every file action; a value written through a link (`~/link/secret`, where `~/link` leads to `/data`) is resolved
once, when the block is written, and the block refuses the real path too (`/data/secret`; `tego block` and the
dashboard say so, and the overlay entry keeps it as `real`, overlay version 4). The block is in force with its value
alone first; the real path is worked out after it, by one walk with a budget (512 lookups, 250 ms), since a governed
agent can plant the links the walk follows, and added in a second write. When the budget runs out the block refuses
the value as written only, and `tego block` says so. A run whose launcher predates the real path (it makes no
`live-real` file in the run directory) gets the value alone: `tego block` names the path left uncovered and the
command that blocks it. A `read` value is the same, for reads only: an open that reads (`O_RDONLY`, `O_RDWR`, `O_PATH`), and
a rename or hard link with either end at or under it, which would give the file a name outside the block; it is
refused (exit 1, `[reads-unseen]`) on a run whose reads tego does not see, where it would refuse nothing. A `write`
value is the same, for changes only: an open for writing, a create, an unlink, a rename or link at either end, a
mkdir, a mknod, a symlink's own name, a truncate and an attribute change; plain reads go on. For every path kind a
rename of a folder above the block is refused too, so a move cannot carry the blocked files out of its reach. Every
path, `read` and `write` block also covers the other names the mount table gives its file when the run's launcher
first sees the block (a bind of the folder or of a folder above it, WSLg's `/mnt/wslg/distro`; ADR 0011, amended
2026-11-19, round 5), under the block's own rule. **Mounts made after that are not seen**: a bind made after the block
was added (or, for the contract's own rules, after the run started) shows the file under a name the block does not
cover, and a block whose other names the mount table could not all list covers those it could, and says so: `tego block` prints a sentence naming the file and the reason, and the run's record gets a `live-block-partial` gap (GAPS C68). A `path`
or `read` block also refuses a watch of what it covers (inotify, fanotify or dnotify, which would report which of its
files are opened and changed; supervisor R36), on a run whose reads tego does not see as well; a `write` block refuses
none. A launcher older than the read and write kinds (a run whose `run_start` has `record_minor` below 24, such as one started
by an older binary) cannot read an overlay holding one: it keeps the blocks it last put in force, writes a
`live-block-unreadable` gap and ignores every later change, `tego unblock` included, until that block is removed. So
`tego block` refuses `read` and `write` on such a run (exit 1, `[launcher-too-old]`; block the `path` instead, which
it enforces), the dashboard does the same, and the Rules page offers such a run a path block for an added
`fs.deny_read` and no write block. After upgrading, rebuild `tego` and `tego-control` together and restart the runs
that should get read and write blocks. At tier 3 (a run whose `run_start` names `decision_plane` `lsm` or
`fmod_ret`) the kernel decides file changes and reads without asking the supervisor, so the launcher puts each `path`,
`read` and `write` block in force in the kernel's decision plane too (ADR 0124, amended 2026-11-21), and makes the run
directory's `live-plane` mark: there a block is **in force** for every change and read the plane decides, a `read`
block may be placed on a run whose supervisor does not see its reads, and the Rules page offers write blocks. On such
a run a block follows the file, not its spelling: a hard link made before a block on that file and a file under a
renamed folder stay blocked (an older hard link to a file inside a blocked folder is not, as at every tier), the rename or removal of a folder or link the block's path runs through is refused, a read block also
refuses deleting or replacing the blocked file, and a block on a path that does not exist yet refuses making its
missing name (and the first missing folder above it). A block keeps every object it landed on until it is removed, so
a file renamed away after the block (by the agent or on the host) stays blocked where it went; each save of a blocked
file by replace (most editors) keeps the old copy blocked and on disk until the block is removed, and about a thousand
of them in one run make the block refuse every change of its kind in the run. A descriptor opened for
writing before the block keeps writing, as everywhere; a write block does not cover a file's timestamps (`touch`) or
its unprivileged inode flags. While any block is on, a file action more than 64 folders below the root is refused as
unresolved anywhere in the run (the plane cannot say no block lies above it). A run whose launcher predates the mark says **partly in force** for a `write` or `path` block, naming
the file changes the kernel decides as not covered, never "in force". A
block only tightens: removing one removes only what it added, never something the contract
refuses. A run that has ended is refused (exit 1, `[not-running]`): nothing would enforce the block; for its next run,
make it a rule of the contract (`tego rule`); `tego unblock` on such a run says its blocks ended with it, and leaves
its overlay as it ended. The dashboard's Block now and Remove make the same checks in the same words (one set,
`liveblock.CheckBlock`, which `tego lift`, `tego grant` and `tego restore` have a twin of in `CheckFence`), so a
Remove posted from a page left open across the run's end is refused too. A block
also outranks a person's answer: a held file open it covers that is waiting for an answer when the block lands is taken
back (its card leaves Approvals; `tego ask` no longer lists it) and refused under the block, and an approval that comes
back after the block landed opens nothing (SEMANTICS §6). A `net` block does the same to a held connect
or UDP datagram (a `net.ask` scope, a gate's ask, a `net.ask unix:` scope, and a first-write hold's ask): the pending
card is taken back within about 50 ms of the block taking effect (the dashboard's answer reads "Withdrawn: a live block
now refuses this") and the connect is refused `live.block[net:...]`; an approval that comes back after the block
landed connects nothing.

A `net` block is on a destination, not on how it is spelled (*since 2026-11-01*). An address is read unmapped and with
no IPv6 scope id, and a block that names this host names all of it: `127.0.0.1:P`, any other `127.x.y.z`, `::1`,
`0.0.0.0`, `::`, `localhost` (or a name under `.localhost`, with no lookup), one of this host's own addresses, or a
host name that resolved to one of these. On the block's port, every connect or send to any of those is refused under
that block, because a server bound to all interfaces answers on each of them and the kernel sends a connect to
`0.0.0.0` to loopback or to the socket's bound source address. So is a datagram to a multicast group, to
`255.255.255.255` or to one of this host's subnet broadcast addresses, which such a server hears too. It costs at most
another local server on the same port, or a group send on it, and a block with no port (`tego block net localhost`)
refuses every group and broadcast send of the run. A group or broadcast address names no host, so a block on
`224.0.0.1:P` refuses that address alone. A block on another machine stays on that machine: it does not follow a
broadcast or group datagram that machine also hears. While tego cannot read this host's addresses at all, a destination
on a block's port is refused, since either may be this host. This host's addresses are read from its interfaces and,
*since 2026-11-02*, from the `local`, `broadcast` and `anycast` routes of the kernel's routing tables its default
policy rules look up (`ip route show table local`, and those routes in tables main and default), so an address of an
AnyIP range (`ip route add local 192.0.2.0/24 dev lo`, or the same with `table main`) is one of its own, a broadcast
address set by hand (`ip addr ... brd`) is one of its broadcast addresses, and a datagram to an IPv6 anycast address
it joined (a forwarding host joins its subnets' router anycast addresses) is refused as a group datagram is; a block
on an anycast address refuses that address alone. Such a route in another table is read when a policy rule you add (`ip rule add from all lookup 100`) leads to its
table and the run's own traffic can match that rule (no `fwmark` the mask covers, `iif` absent or `lo`, a `uidrange`
that holds the run's user; an `oif` or VRF rule counts, since an agent can `SO_BINDTODEVICE` a socket), *since 2026-11-22*; one that only a mark leads to (TPROXY's and
Cilium's tables) is not read, and `tego machine check` names it in a `note routing:` line. Until the tables are first read the interfaces' addresses answer;
once read, the last reading stays in force while they cannot be read again. The `models[]` guard and a `net.allow`
host name's resolved-address check read this host the same way. GAPS C46 lists what the reading of this host's
addresses leaves out.

A `net` block on a host name refuses a connect the contract admits under that name by the name, and every other by the
addresses tego's own lookups of the name answered. Those are every address answered while the block stands (*since
2026-11-02*; before, the last answer alone, and no lookup between changes to the run's blocks): the name is looked up
when the launcher first reads the block, again at each later change to the run's live-block file, and again every
minute on its own, and each answer is added to the ones before; a lookup that fails or answers nothing drops none and
is tried again a minute later. A host is held with at most 64 addresses from those lookups (past that, the one
answered longest ago is dropped), besides what the lookup at the last change answered, which is never dropped. Under a
contract with no `net:` section nothing admits a connect by name, so those addresses are all a block matches: an
address the name's DNS gives the agent before tego's lookups have answered it, such as a CDN's next rotation, is not
refused until one does. A removed block takes its addresses with it, and the same block added later starts from a new
lookup. A host an Adjustable run's fence also names (ADR 0125) is held for the whole run, and looked up every five
minutes while no block names it.

A block is matched against the address the supervisor copied from the agent, so what a thread of the agent does after
that check matters (*since 2026-11-01*). While any `net` block exists, every connect and TCP Fast-Open send on an IP
socket is performed by the supervisor on that copy, whatever the contract says, so rewriting the address afterwards
reaches nothing. Two things stay as they were, and a thread racing the check can pass a block through either
(GAPS C47). An addressed datagram is sent by the kernel from its own read of the address: one whose copy the block names
is refused, and one a sibling rewrites after the check is sent there under a line that says `best_effort: true`. And
under a contract with no `net:` section and `host_sockets: true`, a connect on a socket that is not IP stays the agent's
own, with its own credentials and Landlock scope: a sibling can rewrite a unix path to one a block names, or swap an IP
socket onto the descriptor and rewrite the address. Under a `net:` section, and with no `net:` section and no
`host_sockets: true`, the supervisor performs those connects too.

What a block does to the run is said in one word, here and on the dashboard (`tego block --list` prints it beside
each block, `--json` as `state`): **in force** once the launcher has written the gap line confirming it (about half a
second after the write), **partly in force** for a write or path block on a run whose kernel decides file changes and whose launcher
predates putting blocks in the kernel too (`state` `partly_in_force`: the supervisor refuses what reaches it, the
kernel's own answers are not covered; a launcher that makes the run directory's `live-plane` mark puts them there, and
its blocks read **in force**),
**waiting** until then, **refuses changes only** for a path on a run whose reads tego does not
see (held reads, `fs.reads: held`, or `record: full` let it refuse reads too), and **recorded, not enforced** on a
`tego watch` run: a watched run refuses nothing, so a block there is written and marked on each matching line while
the agent goes on, and `tego block` says so (`recorded, not enforced: run <id> is a tego watch run`, exit 0). A
`tego unblock` from inside a run's cgroup is refused (`[governed]`): a governed agent may tighten a run, never loosen
it. A `tego block` from inside a run is refused too unless it names that same run (`a process inside a tego run cannot
change another run's governance`, `[governed]`, exit 1): an agent may narrow its own run, never another's, which it
could starve while the record showed the block as placed from a terminal. The caller's own run is read from
`/proc/self/cgroup`; a caller that looks inside a run but whose run cannot be named is refused whatever it names. A same-uid process can still write the overlay file directly; a `tego watch` agent is unconfined.

## Precommit modes (2026-10-28)

`scripts/precommit.sh` has three modes. The policy is fixed: **every merge to main runs the full gate**; the scoped
and docs modes are for in-between checks (an agent's run before it hands a branch over, a merge queue's early
rejection) and never replace it.

| Mode | Command | What runs |
|---|---|---|
| Full (merges) | `make precommit` | Every step on every package, as CI's build-test job. |
| Scoped (in-between) | `make precommit-affected BASE=<rev>` (or `TEGO_PRECOMMIT_SINCE=<rev> scripts/precommit.sh`) | What `tools/affected` selects for the change since the merge base of HEAD and `<rev>` (default `main`). |
| Docs (in-between) | the same command, when only Markdown changed | `rulecheck`, `check-spdx` and the tests that read Markdown. |

Markdown under a global directory (`scripts/README.md`, `tools/README.md`, `test/vm/*.md`, `.github/*.md`) takes the
full gate like any other file there: the gate's scripts may read it, and the selection does not try to tell. Only the
full gate prints `precommit: every step passed`; the scoped and docs modes end with `precommit: every selected step
passed (<mode> mode since <rev>; not a merge gate)`. `make precommit` and `.githooks/pre-commit` clear an inherited
`TEGO_PRECOMMIT_SINCE`, so a variable left in a shell never turns the merge gate into the scoped check.

**Parallel full gate.** The steps run in three phases: the static checks (gofmt, the four vets, both golangci-lint
runs, check-spdx, check-licenses, shellcheck, check-skiplists, check-exits, check-fd, rulecheck, isocheck,
bpf-objects, the script self-tests, actionlint, deadcode-report's ratchet) concurrently, the lint job (the longest)
started first; then the unit tests, followed in the same job by the tegotesthooks tests; then the integration tests,
with the browser tests (`-tags chrome`) in a job of their own beside them, and, where `tools/oss/cut_test.py` is, the unrestricted public cut-tree
target (`scripts/oss-cut-test.sh --discard-tree --jobs N --timeout S`, N the gate's job budget and S `TEGO_PRECOMMIT_OSSCUT_TIMEOUT`, default 2700 seconds; its evidence line in `<scratch>/osscut/evidence.jsonl`) in a third. `TEGO_PRECOMMIT_JOBS` caps the jobs running at once; the default is
min(nproc/2, GB/2, idle cores/2), where GB is the lower of MemAvailable and the least that any of the process's cgroups has left
(`memory.max` less `memory.current` without its `inactive_file` page cache), idle cores are the CPUs less the one-minute
load average, and the result is never below 1. The gate prints a line before the first step that says what each limit
allowed and which one decided (or that `TEGO_PRECOMMIT_JOBS` did). The browser tests run when `google-chrome` (or
`$TEGO_CHROME`) is on PATH, with the eleven matrix tests named in `matrix` in scripts/chrome-tests.sh left out unless
`TEGO_PRECOMMIT_CHROME=full`; a skip in them fails (the three operator tools that need a person's variables are left
out by name). Without the browser, or with `TEGO_PRECOMMIT_CHROME=0`, the step prints `NOT RUN: <reason>`, the gate
exits 3 and its last line names what did not run and does not say every step passed. Every test
pass gets `go test -p <jobs>` and `-count=1`: go test's result cache rechecks only the files the test process itself
opened, so a test whose verdict comes from a `go build` or `go list` it runs, or from a binary it built (the link
gate in internal/control, askclient's and capture's import checks, examples/supply-chain-demo,
internal/control/web/e2e and the other binary-closure suites), would replay a stale pass. The two golangci-lint runs
and the script self-tests share one job: golangci-lint refuses a second instance while one holds its lock ("parallel
golangci-lint is running", which the gate wrapper retries on), and check-fd_test.sh and check-edgelint_test.sh run
it. Each step's output goes to its own file and is printed in the fixed order, with its duration, whatever finished
first; a step that fails prints its output; a step that is killed (a signal, or its job's shell killed before it
wrote its status), or never reported (its phase never ran), is a FAIL, never ok; a step of an unknown phase is
refused and fails the run; an interrupt stops the running steps and everything they started. `TEGO_PRECOMMIT_JOBS=1` runs the steps one after another in the order they were added
(the order above); its output differs from the old serial gate's only by the durations and the "N job(s) at once"
line. scripts/precommit_test.sh holds the runner to this.

**Scoped selection.** `go run ./tools/affected -base <rev>` prints the selection and why (`-plan` adds the
directives precommit.sh reads). It lists the changed files (committed, staged, unstaged, untracked, deleted) and
classifies each:

- a global input (go.mod, go.sum, Makefile, `.golangci.yml`, `.github/`, `.githooks/`, `.goreleaser.yaml`,
  `scripts/`, `test/vm/`, `test/e2e/`, `test/*-skips.txt`, `tools/`, `internal/testutil/`, `bpf/`, `internal/bpf/`, `.gitignore`,
  LICENSE, NOTICE, THIRD_PARTY_NOTICES.txt, `LICENSES/`,
  a nested go.mod, a shell script outside a Go package, any `*_test.sh`, a test file that takes its directory on or off
  the tegotesthooks list, a file no package owns or names, a Go file of a directory no build lists): the full gate,
  with the reason printed;
- Go source: the package and every package whose build or test binary depends on it, per build (default,
  integration, tegobpf, integration+tegobpf, tegotesthooks; `go list -e -test -json ./...`, about 4 s for all five);
  a `_test.go` file: that package's tests; an embedded file: the embedding package; testdata or another file under a
  package's directory: its owner's tests (a deleted one, Markdown included: the owner's source, since it may have been
  embedded); a path a test names by literal (the leading literal arguments of a `filepath.Join` or `path.Join` call
  count as one path; a package directory above the test's own, a bare `".."`, is not a read of everything under it),
  or a known reader (`spec/record/` is `pkg/spec/record`'s, `examples/` is `pkg/spec/agent`'s):
  those tests. Scoped mode runs no script self-test, so the files they read are global inputs too:
  `internal/control/web/testdata/edgelint/`, `test/workloads/build/`, `test/workloads/python-httpx/agent.py`, and the
  two Go test files test/vm/fetch-kernel_test.sh reads tables from (`internal/platform/peer/peer_test.go`,
  `internal/runtime/enforce/landlock/integration_abi_test.go`). tools/affected's TestSelfTestFixturesAreGlobal holds
  every file a self-test names, and every fixture, to a global input. precommit_test.sh also holds two rules over the
  tree, which scoped mode keeps by going to the full gate: every `*_test.sh` is in ci.yml, and the tegotesthooks list
  in precommit.sh and ci.yml is the set of directories with test files behind that tag. Each integration build is
  listed both with `CGO_ENABLED=0`, as its tests run, and with go env's setting, as its vet runs, and the two are
  merged.

Two rules add tests whatever changed. The **source scanners** always run: tests that read the tree rather than import
the changed code (a walk, a parse of Go files, a repo-root path, `".."`), found by scanning test code and seeded with
`internal/askclient` TestLedgerTargetSingleSource, `internal/control/linkgate_test.go` and `pkg/spec/agent`
TestLiveOffGolden and `internal/runtime/capture` TestCaptureLinksNoEngine; a test the scan can name runs alone (`-run`), a read it cannot pin to a test runs the package
(benchmarks aside: go test runs none without `-bench`). The **binary closure**: a package whose tests name a module
package by its path (cmd/tego, cmd/tego-control, a test workload: `go build`, `go run`, `go list -deps`), or whose
test binary links a helper whose own code names one, runs when the change reaches that package's dependency closure
in any build (a `./...` or `.../...` pattern names every package under its directory, one the change adds included,
so a test that runs `go list ./...` over its own subtree runs when a new package there links something new), so `examples/supply-chain-demo` and `internal/control/web/e2e` run for a change anywhere under
cmd/tego. A deleted file under a package counts as that package's source (it may have been embedded), and
`test/e2e/`, where the shell self-tests live, is a global input.

When tools/affected gives no plan (a base git does not know, a tools/affected that does not build), the scoped
command runs the full gate. The scoped run then does gofmt, the vets over the affected packages per build, both
golangci-lint runs over the same affected packages (an enum value added in one package breaks `exhaustive` in an
unchanged one that switches over it), check-spdx, check-licenses (a Go-only change can link a new third-party
package), check-skiplists, check-exits, check-fd, rulecheck, isocheck, shellcheck over the changed scripts (a note
when it is not installed), and the selected tests through the same `gated-test.sh`, skip lists and `-count=1` as the
full gate; a build's test and `-run` lines share one job, and the tegotesthooks lines the unit job. What it
cannot see (a test reading the tree by a path built at run time from parts the scan does not recognise, a script a
Go test runs by a computed name) is why merges keep the full gate.

## Logs of tego itself
`~/.tego/tego.log` (tegod instances, when a trigger builds them, log to the journal; ADR 0042), rotated at 10 MB, 5 files, `0600`, one structured
line per event with `run=<id>` when a run is involved; never the agent's data, never an event that belongs in the
ledger (dropped ring-buffer events are a `gap` event, a budget hit is a `limit` event, an orphaned run is
`run_end reason=orphaned`). Rotation takes a lock on `~/.tego` that any process of the user's uid can hold,
the agent included; while another process holds it the file grows to at most twice the limit, after which lines
are dropped, and the next rotation begins the new file with how many were. The level is `log.level` in the machine
config. `~` is the invoking user's home from the passwd database, so under `sudo` the log is the invoking user's
and the files a root run creates for it are handed to that user — only files and directories that process itself
created, never one it found already there. `$HOME` is read only by an unprivileged process without `AT_SECURE`
whose uid has no passwd entry; one with no passwd entry that runs with `AT_SECURE` or as root keeps no log.
`-v` (mirror the log to stderr) and `--log-level` are not built yet: they are global flags `cli.Main` would parse
before dispatching a command, and until it does the machine config is the only way to set the level.

## What a message shows of the environment

One rule covers every diagnostic, warning, error, log line and dashboard text (its statement in the code is
`pkg/spec/identity/envtext.go`):

- **Never printed, whatever its length:** the value of an entry of the agent's environment. That is the contract's
  `env` section (`set` and pass-through entries), a harness entry, a credential, and anything read from another
  process's environment. The message names the variable. An entry so malformed that its name cannot be told from
  its value (a secret pasted where a name belongs) is called by its position, and nothing of it is echoed; a bare
  secret that is itself shaped like a variable name (`ghp_abc123`, with no `=`) cannot be told from a name, and is
  shown as the name.
- **Never echoed:** a value that failed validation, of any variable: a run id that is not a run id, a path variable
  that is not an absolute clean path of printable characters (a `TEGO_CONFIG` of `/etc/x/../config.yaml` is read,
  and its messages call it `$TEGO_CONFIG`). The message names the variable, says what is wrong, and says how to
  print the value yourself (`echo $NAME`).
- **Printed where the message is about it:** a place Tego resolved from a location variable and validated (`HOME`,
  the XDG folders, `TMPDIR`, `TEGO_CONFIG` and Tego's other path settings, `TMUX_TMPDIR`, `SCREENDIR`, a `PATH`
  directory), exactly as a place given by a flag or a settings file is printed, and a Tego identifier that passed
  validation (a run id, a parent run id, the invoking uid). You see which file is malformed and which folder could
  not be made.
- **Displays and exports are not diagnostics.** The rule table, the effective settings, merged YAML and JSON show
  what was asked for. The rule table names an entry whose value comes from the caller's environment and says where
  it comes from (an inherited `PATH` reads `PATH, inherited from the caller's environment`); a value written in the
  contract file is shown as the file has it, and the dashboard's editor shows each `env.set` value as
  `(value hidden)`. The machine forms (`--json`, `--merged`, the saved `contract.yaml`, a sighting's JSON line)
  carry values: treat their output as you treat the contract file.

An inherited `PATH` is both a pass-through entry and a list of places: the rule table names it only as inherited,
and an error about a program that was not found lists its directories (`searched: …`), because that message is
about those places; an `env.set PATH` is never printed.

What protects you is keeping secret-capable values out of messages, not hiding places.

## Contracts found on this machine

`tego rules list [--json] [-v]` lists contracts in the current and recorded project registries, the configured user
registry and contract sources of runs in the selected ledger root. Each row gives its offline check result,
contract hash, last recorded start and tier, and whether that run's canonical contract hash matches today's source.
The scope footer and consulted roots always appear. `-v` (also `--verbose`) gives full hashes, context and warnings.

`tego rules list <name|path> [--json] [-v]` shows the selected contract's compiled rules and sources. Names
across the catalog must be unique. An explicit path skips discovery, but a saturated helper budget can still
leave that file unchecked. Use a path for an ambiguous name or incomplete discovery. Sources
include file and line, profiles, presets, built-in defaults and machine-config ceilings. Verbose output includes
`tego rules check`'s table. JSON names `tego.contracts.v1` and `tego.contracts.show.v1`; see
[the schema](../../spec/contracts/v1/README.md) and [the user page](../site/testing-rules.md).

The view writes nothing and adds no rule. It loads machine config with TrustAbort, defers DNS without sending a
lookup, inspects programs on the caller's PATH without executing them, and prepares no backend. Recorded starts
are metadata, not chain-verified proof. Missing owner/project context is incomplete. Exit 0 is a complete check,
1 a contract finding or ambiguity, 2 usage, and 125 unsafe/unreadable input, incomplete discovery or I/O failure.
The systemd agent example already uses the user registry. No separate deployment/service registry exists on this
base, and this command never scans arbitrary systemd units or other homes.

The command carries a 60-second deadline; each contract check and registry scan stops waiting after 5 seconds.
Registry scans, complete source checks and selector walks run in a helper reexecuted from `/proc/self/exe`.
The caller reaps its short launcher before sending any recorded path. One worker serves sequential checks
for one command or for every check belonging to a dashboard page, with a replacement after abandonment.
Guide bootstrap, change-feed and link-reference reads take that page request and session. Credentials are compared
before each request. The worker retains an empty environment. The caller freezes its identity, homes, runtime bases,
IPC paths and working-directory facts before dispatch; selected config snapshots, ledger/registry/profile locations,
anchor and PATH are explicit check inputs. A request without caller context is refused;
secret-environment warnings use names only. Evaluation time is selected before dispatch. Active resolver settings
which cannot be reproduced give added hostnames a cannot-tell preview warning; their values never enter the helper
environment. The next run resolves hosts independently. Frames remain capped at 128 MiB.
At most 32 workers remain alive per effective uid and network namespace across commands and page requests.
Abstract Unix socket reservations survive in inherited fd 2 until actual worker exit. Closing a caller's pipes
cannot release an abandoned worker's shared reservation. Each caller process also has 32 local worker slots.
Concurrent starts can briefly add 32 short launchers. This finite capacity accommodates 16 healthy commands
with 16 slots of headroom, rather than refusing ordinary concurrency at the old four-worker limit.
Reservation squatting can deny service but cannot inject replies. Exhaustion, reservation failure and changed
post-exec credentials all refuse checks; entries remain incomplete and name the reason. See
[healthy-machine measurements and the refusal matrix](../testing/contracts-helper-cost.md).
The dashboard routes recorded and user-supplied path work through the same helper from the control binary.
Unavailable entries remain listed, say `cannot tell: this location does not answer (a disconnected or stuck mount?)`
(only after the checker reported it was about to touch the location, five seconds passed, and the kernel's counters for
the checker (`/proc/<pid>/task/<tid>/stat` and `schedstat`, read from the checker's own pid) say it was in uninterruptible
sleep or mostly asleep, neither waiting for a CPU nor running on one for half of the window; a checker
that was starved, waiting on a run queue for at least half of the window and not in uninterruptible sleep, is given another
five seconds, again while it stays starved, to 20 seconds of location time in all for a check or a page, and then says `cannot
tell: Tego's checker was too slow to finish (the machine is very busy); try again`; a checker that was on a CPU for at least
half of the window is given the same extra time and says `cannot tell: the check was still working when its time ran out; try
again` at the cap; where the counters cannot be read (a kernel
built without `CONFIG_SCHED_INFO` has no `schedstat`) it says `cannot tell: the check did not finish in time (a stuck location,
or a very busy machine)`; a checker that was blocked in this computer's own disk or journal (the kernel's `wchan` of its
blocked thread is `jbd2_*`, `ext4_*`, `xfs_log_force*`, `btrfs_commit_transaction*`, `io_schedule*`, `folio_wait_bit*`,
`wait_on_page_bit*` or `blk_mq_*`) is given the same extra time as a starved one, to 20 seconds in all, and then says `cannot tell:
this computer's disk did not finish writing in time (the disk is very busy or nearly full); try again`, and a thread blocked in a network or user-space filesystem, in a name
Tego does not know, or that cannot be read, still gets the mount words, unless every location the check declared is on this computer's own storage (read from `/proc/self/mountinfo`, never from the location: ext4, xfs, btrfs, f2fs, bcachefs, zfs, tmpfs and the kernel's own filesystems, vfat, exfat and squashfs on a device node, and an overlay whose layers are all on such a mount): that check, if its helper has a thread in uninterruptible sleep when the five seconds end, is a disk wait whatever the helper's wait function says (it is hidden for an undumpable process); such a helper is given up to 30 seconds (`StartTimeout`; a dashboard request's own 25 seconds end it first) before the disk words; a helper that is only asleep, or whose counters cannot be read, keeps the words above at five seconds, and a thread readably in a network wait still gets the mount words; a request that finds every helper slot held by checks stuck on this computer's disk gets the disk words, and one holder stuck on a mount is enough for the mount words (ADR 0144, "A local location is a busy disk, not a stuck mount"); a checker that did not
start within 30 seconds on a very busy machine says `cannot tell: Tego's checker did not start in time (the machine
is very busy); try again`, and nothing was asked of the location; a checker that could not start at all says `cannot tell:
Tego's checker could not start: <reason>`, which also asked nothing; a caller that gave up says `cannot tell: the check was
cancelled before it finished`; and while every helper slot of this process is held by a check stuck on a location the
next check refuses at once, in the first words, naming how many earlier checks are stuck, instead of waiting for a slot
that cannot come free; so does a pool held by other commands' checkers when every one is older than any check can live, 115 seconds: it says
`N earlier checks are still stuck on a location that does not answer`, and a pool with any younger or unreadable holder keeps the wait). A dashboard page's checks together are bounded by the server's own write deadline less a five second margin (25 seconds of its 30), so a page whose checks wait for a helper slot, a start or a mount is answered with the same words, and its unavailable entries, instead of having its connection closed with no response; the live stream and the commands are not bounded that way. A draft compile is not the location: the helper stops the five seconds while it compiles, the
compile has its own 30 seconds to start and then its own three (the same counters extend them for a starved compiler child, to
20 seconds in all), and one that does not finish says `cannot tell whether the new contract compiles: the check did not finish in time (the
machine is very busy); nothing was written; try again` when its child was starved to the cap, `... did not finish in time;
nothing was written; try again` when it was not (claiming no cause), `... the compiler is busy with other checks ...` for a
full compiler slot and `... Tego's compiler could not run ...` for a compiler that could not start, died or returned no
result, never "does not compile"; and disable changes and trust-dependent actions even when metadata answers but source or profile reads fail.
The Rules page receives a recorded projection before checking the source: two exchanges share one worker and
one overall deadline. If the source or profile read blocks until that deadline, the received rules, redacted
YAML and recorded hits remain visible at copy positions with the unavailable reason. Source comparison is
absent; source edits and trust-dependent actions stay disabled. All loader diagnostics are checked for
unavailable causes, including after an ordinary error. Earlier guard refusal reasons remain visible. This
requires the ledger and copy to answer. The fallback uses recorded text without compiler probes and makes no
fresh compilation or enforcement claim. Timed-out pipe exchanges leave no handler waiting for recovery.
A change already submitted can have an uncertain outcome after a timeout; reload after recovery before retrying.
Late replies are discarded; a worker in a dead mount can remain until recovery. Initial selected config and
ledger I/O, plus caller identity/current-directory capture, remain synchronous and require responsive locations. Actual dead-mount CLI/dashboard process return,
helper disappearance after abort, and root/sudo/other-uid checks are a **MERGE BLOCKER**, **owed in a guest**:
[complete recipe](../testing/contracts-stuck-mount.md). A recorded hash is shown
only if it has the SHA-256 format; unknown tiers are labelled `unknown`. The table's `SAME TEXT AS LAST RUN` compares merged text, not effective rules.

Fix round 5 obtains a known run view before location metadata and catalogue source reads. A catalogue read that blocks
uses the same overall request budget and cannot discard the recorded view or start a replacement worker
after that budget expires. A canonical alias that cannot be resolved may still leave the selection unidentified.


## Entry diagnostics and process-id namespaces (2026-11-18)

Doctor, `machine check`, setup and start keep the original shell while a short-lived user-scope helper may rehearse
placement. `--no-scope` on machine check and setup suppresses that helper. Success replaces only the placement check;
delegation, controllers and atomic cgroup kill must still pass. The stored shell check can say
`through_user_scope: true`. It neither moves the guide nor changes `as.in_user_cgroup`. A failed rehearsal prints
its cause and leaves the in-place report's exit unchanged. Run, watch, test and `machine test` use the existing
handoff; `run --service` retains its own unit. The helper validates the entire environment before readiness, keeps
the first duplicate name, reports a reason byte and never dispatches a rehearsed command. ADR 0142 records the protocol.

Root tiers require the kernel's initial process-id namespace in addition to root in the initial user namespace.
Doctor checks that fact before root-tier cache, pin adoption and functional probes, and does not list or sweep
PID-indexed root state when it cannot establish it. Auto selection can use landlock when its checks pass; an
explicit cgroup/bpflsm selection refuses. Compile and the run-start compiler name that namespace precondition
instead of suggesting another build; a genuinely absent build tier keeps the build warning.
In the WSL 3.0.5 guest the specified trace measured a shell PID of 4058 and BPF TGID of 4299. That explains the LSM plane's descriptor lookup mismatch; fmod_ret also had a separate
`security_key_permission` known-answer failure. Neither is repaired by hiding a failed functional probe.
Ordinary WSL admission remains refused. The first proof was stopped on the unreadable manager namespace; the rule
that replaced it (ADR 0100, amended 2026-11-18) is built and is off on WSL in an ordinary build, where every
command that needs a proven "outside" answers `[governed]` with the reason that the refusal of WSL's own launcher
inside a run is not proven yet. Read that line as "not supported yet", not as a fault of the machine. The other
reasons a person can act on lead their line: no systemd at the top of the cgroup tree, a user session that is not
up yet, and root. See ARCHITECTURE section 13 and GAPS.

WSL machine check reports retain the measured kernel tier but include four pending containment warnings and return a
finding instead of readiness. Setup withholds a ready stored tier for that report. `WSL_INTEROP` is omitted from
enforcing runs; this environment filter alone does not prove launcher containment. See GAPS for the open rows.
