# ADR 0113: Built-in refusals in every run: host IPC that escapes the run, Tego's own surfaces, and the person's other terminals

Status: **accepted 2026-10-24**; implemented 2026-11-03, with the limits below. Amends SEMANTICS section 1's "no `net:`" row with the exception below, and
composes with [ADR 0070](0070-host-sockets-refused-by-default.md): its refusals hold under a `net:` section and under
`host_sockets: true`, and in the unix-only state ADR 0070 already refuses these sockets.

## Context

A run with a contract that allows some host socket can reach more than its own processes. Such a run can:

- reach the session bus and the systemd user manager, so `systemd-run --user` starts a process outside the run's cgroup. Every
  Tego check that says "a run member is refused" is a cgroup check, so that escaped process passes all of them: an ask broker
  that answers any caller outside a run, the dashboard's POST checks;
- reach the X server's pathname socket, which takes synthetic keystrokes, so an agent could type into the person's terminal,
  an approval prompt included;
- reach every other same-uid pathname socket outside the run, and so the servers that run commands or type into terminals: a
  terminal multiplexer (tmux beneath `/tmp/tmux-<uid>/`, GNU screen beneath `/run/screen/S-<user>/`), a terminal emulator's
  remote control, an editor server (Neovim, Emacs) and the AT-SPI accessibility bus, which generates keystrokes.
  `tmux send-keys -t <pane> yes Enter` or `screen -X stuff` types into any pane, and `tmux capture-pane` reads one;
- probably open another of the person's terminals for reading (`/dev/pts/<N>` is on no deny list) and race the shell for its
  input, such as a typed passphrase.

Tego's own directories (the ledger root, the chain anchor, the machine config) are already read-denied in every enforcing
run (agent-contract R6a), so such a run cannot read the ledger root, which holds each run's directory and sockets. There are
two exceptions. A ledger root that also holds what the run needs (the contract, the working directory, the home or a write
entry) is not denied, and `compile` warns `ledger-readable`. A record-only run (`tego watch` with no `--boundary`,
`tego run --observe`) has no Landlock ruleset at all, so nothing denies it. [ADR 0125](0125-locked-and-adjustable-modes.md)
relies on the deny for the live lift key, so an Adjustable run does not start without it. This record closes the sockets and
terminals that are outside those directories. `TIOCSTI` and `TIOCLINUX` on the run's own terminal are already refused by tier
1's seccomp filter.

## Decision

**(1) The refusals.** For every contract, whether its `net:` section is present or absent, `compile` adds built-in refusals
that neither `net.allow` nor `deny_read` (`deny_read: []` included) can remove, as R6a's own-files deny:

| Rule id | Refused |
|---|---|
| `builtin.host_ipc` | a pathname connect, or a datagram send to a pathname address, to a socket beneath `%U` (the D-Bus session bus, the systemd user manager, Wayland compositors, the AT-SPI bus, terminal-emulator, editor and audio servers), except the run's own runtime directory and the SSH-agent sockets of (2); `/run/dbus/system_bus_socket` (the system bus); `/tmp/.X11-unix/X*` (X servers); beneath the multiplexers' and editor servers' per-user directories outside `%U`: `/tmp/tmux-<uid>/` and `$TMUX_TMPDIR/tmux-<uid>/`, `/run/screen/S-<user>/`, `/var/run/screen/S-<user>/`, `$SCREENDIR` and `~/.screen`, `/tmp/emacs<uid>/`, `/tmp/nvim.<user>/` (each such directory, and `%U` itself, is also a built-in `deny_write` target, below). At Landlock ABI 6 and later, every abstract name bound outside the run. A FIFO in those directories is in the built-in `deny_read` and `deny_write` sets. Beneath `%U/tego` the rule is `builtin.tego_surface` |
| `builtin.tego_surface` | a connect to every Tego socket: every `ask.sock` beneath the ledger root, and beneath `$XDG_RUNTIME_DIR/tego` except the run's own runtime directory (`$XDG_RUNTIME_DIR/tego/<run id>`, which holds the agent's generated `CODEX_HOME`, agent-contract R10a) |
| `builtin.other_tty` | a read or write open of a pty slave (`/dev/pts/<N>`) or a virtual console (`/dev/tty<N>`, the `/dev/tty[0-9]*` names), other than the run's own controlling terminal and the ptys the run allocated itself ((3)). The multiplexor (`/dev/ptmx`, and `/dev/pts/ptmx`), `/dev/tty` (which names the caller's own terminal) and serial devices (`/dev/ttyS*`, `/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/ttyAMA*`) are not refused by this rule |

`%U` is the invoking user's runtime directory, `/run/user/<uid>`. A path is resolved as R6 resolves a `net:` unix entry's
(supervisor R11): on the name passed, then on the path of the inode reached (`/proc/self/fd/<n>`, the kernel's `d_path`). That
catches a symbolic link and a bind mount that name one of these sockets from elsewhere. It does not catch a second name for
the socket itself: for a hard link, or for a refused directory moved to another name, `d_path` gives the new name, which is
beneath no listed directory. Three more checks close that:

- *Identity at connect.* The supervisor already holds the reached socket open (`O_PATH`) and decides on that descriptor, so it
  refuses, rule `builtin.host_ipc`, a socket with `st_nlink` above 1 (a hard link), and a socket whose directory's device and
  inode match one a refused directory had at `Prepare` (`Prepare` records the device and inode of each refused directory that
  exists then, after following any link the name is). So a directory moved after `Prepare` is refused under its new name.
- *The refused directories are built-in `deny_write` targets.* Each listed directory outside `%U`, and `%U` except the run's own
  directory, is a target as R20's built-in set is: a run may not rename, link, unlink or create an entry in or beneath one, nor
  make, rename, remove or replace the directory itself, whatever its write entries say. This set has no opt-out. The planes
  decide it race-free, keyed by the parent directory and the entry's name, so a name that does not exist yet is covered too.
  Where no plane decides the run (tier landlock, and the fanotify fallback) the supervisor refuses it on the copied pathnames
  (supervisor R15c), which a racing thread can defeat ("What stays open").
- *Landlock's own rule.* A link or a move between directories needs `REFER`, and the kernel refuses one that would give the
  file more rights where it lands than where it was. That is a backstop for a refused directory outside every write entry, not
  the mechanism.

`$TMUX_TMPDIR` and `$SCREENDIR` are read from the invoking environment at compile time and only ever add refusals: no
exception comes from the environment, so an agent that edits the person's shell start-up files between runs cannot move a
socket out of the list.

The sockets a run's agent is meant to use stay reachable: its own DNS broker socket (in a private directory beneath `/tmp`)
and anything in its own runtime directory.

**What stays open (disclosed).** A same-uid server outside the run that runs commands or injects input at a path this list
does not name stays reachable from a contract with no `net:` section: a multiplexer started with a socket path of the
person's choosing (`tmux -S <path>`), kitty's `listen_on unix:<path>`, an application's own control socket beneath `/tmp` or
the home. Below Landlock ABI 6 every abstract name does too. Where no plane decides the run (tier landlock, and the fanotify
fallback), a racing thread can defeat the supervisor's copied-path check on a move of a refused directory made after `Prepare`,
on a move of a socket out of one, and on making a refused name that does not exist at `Prepare`. And at tier landlock an
admitted datagram is `CONTINUE`d (supervisor R13b): the kernel reads the address again, so a racing thread can redirect a
datagram aimed at an admitted name to a refused socket; tier cgroup on 6.7 and later and tier bpflsm decide on the kernel's own
copy. A contract with a `net:` section refuses every pathname connect it does not name (SEMANTICS section 1), so it closes the
first of these as well; `compile`'s R19 warning for a contract with no `net:` section says so.

**(2) Container daemon and SSH-agent sockets.** Container daemon sockets (Docker, Podman, containerd, rootful and rootless,
`%U/docker.sock` and `%U/podman/podman.sock` among them) are refused by default. A `net.allow` entry naming the exact socket
path admits one, and `compile` warns `container-socket-escape`, saying that the daemon starts containers outside the run;
this is the one place `net.allow` reaches beneath `%U`. The SSH-agent sockets keep today's R19 warning and are not refused:
gpg-agent's SSH socket (`%U/gnupg/S.gpg-agent.ssh`), `%U/openssh_agent`, `%U/ssh-agent.socket`, `%U/keyring/ssh` and
`%U/gcr/ssh`, and any SSH agent socket outside `%U` (`/tmp/ssh-*`). Agents use them for git over SSH, and the SSH agent
protocol carries no terminal and no prompt text. gpg-agent's other sockets are refused (`S.gpg-agent`, `S.gpg-agent.extra`,
`S.gpg-agent.browser`, `S.dirmngr`, `S.keyboxd`, `S.scdaemon`): a client of the main socket can name the terminal pinentry draws
on and the text it shows, and gpg-agent starts pinentry, scdaemon and dirmngr outside the run. What stays with the SSH sockets:
they sign with the person's keys while the keys are unlocked. The list is fixed in `compile_hostsock.go`; a new exception is an
amendment of this ADR.

**(3) Per tier.**

- *Connect, datagram send and bind.* At tier landlock the supervisor decides connect and bind on frozen arguments for every
  contract (bind is newly notified for a contract with no `net:` section), and an addressed `sendto` or `sendmsg` as supervisor
  R13b does: a refused destination is refused before a byte leaves, and an admitted one is `CONTINUE`d and read again by the
  kernel, so it is best effort. It decides link, rename, unlink and create against the built-in `deny_write` targets of (1) on
  the copied pathnames (R15c). The abstract-unix scope is on at ABI 6 and later for every contract; below ABI 6 abstract names
  are not refused, which `doctor` reports and `run_start.capabilities` (`net.unix_abstract_scope`) records. Tiers cgroup and
  bpflsm apply the same refusals as plane rows, and the targets as rows keyed by parent directory and name.
- *Other terminals.* Every tier gives the run a Landlock domain, and the domain is what refuses: beneath `/dev/pts` and among
  `/dev/tty[0-9]*` it grants only the run's own controlling terminal's node and `/dev/pts/ptmx`. The run's own ptys reach it
  through the supervisor:
  - `ioctl(master, TIOCGPTPEER)`, which glibc's `openpty` and `forkpty` use (and so Python's `pty`, node-pty, `script(1)` and a
    tmux or screen inside the run): the seccomp filter notifies that request number; the supervisor takes the master with
    `pidfd_getfd`, checks it is a pty master, performs the ioctl itself, outside the run's domain, and installs the slave in the
    agent with `SECCOMP_IOCTL_NOTIF_ADDFD`;
  - an open of the slave by path (`ptsname` and `open`, as Go's creack/pty and musl's `openpty` do): the filter notifies an
    `open` or `openat` whose flags carry `O_NOCTTY`. When the frozen path is exactly `/dev/pts/<M>`, the supervisor looks for a
    pty master a run member holds open whose `tty-index` is `M` (its `/proc/<pid>/fdinfo`), takes it with `pidfd_getfd`,
    checks that `TIOCGPTN` answers `M`, performs `TIOCGPTPEER` on the duplicate with the open's flags, and installs the slave it
    gets. It never opens a path. The duplicate holds the master open, so its index cannot be freed and handed to another pty
    while the supervisor works. When no held master passes, or the master was closed first, the open continues and meets the
    domain, which refuses it;
  - the person's terminals have their masters in a terminal emulator or multiplexer outside the run, so their indexes are never
    a run member's. The planes add no pty row: the domain and the supervisor decide at every tier.

**(4) The record.** A refusal writes an ordinary refused line naming the built-in rule id (`builtin.host_ipc`,
`builtin.tego_surface` or `builtin.other_tty`) with the reason a refusal of that kind records today (`net-not-allowed` for a
connect, send or bind, `read-denied` for a read, the built-in `deny_write` set's reason for a write), so no new reason value and
no record minor is needed. At ABI 6 and later the supervisor refuses an abstract destination whose run origin is outside or
unknown with `builtin.host_ipc`, rather than continuing mutable arguments. The Landlock abstract
scope remains installed. Below ABI 6 the abstract-scope residual remains disclosed.

**(5) The SEMANTICS exception.** The "no `net:`" row of the SEMANTICS section 1 table becomes: "deny nothing, except guarded
`models[]` endpoints under `capture: forwarder` and the built-in refusals that hold in every contract (ADR 0113); `compile`
warns naming the well-known host daemon sockets that stay reachable (agent-contract R19)". A paragraph after the table, with a
dated Changes entry, lists the refusals of (1) to (3) as this record states them.

## Rejected options

- *Keep R19's warning only.* Every "run members are refused" check would be bypassed by `systemd-run --user`, and X11 types into
  the person's terminal.
- *Refuse only while the dashboard runs.* An agent can wait for it to stop, and the person's terminals need the protection
  whether or not the dashboard exists.
- *Read "no `net:`" as deny-all.* That breaks every contract written for SEMANTICS section 1 as it stands; the refusals here are
  narrow and name what they close.
- *Refuse every pathname unix connect outside the run in a contract with no `net:` section.* It would close every same-uid
  server at once, but it breaks name resolution through nscd and systemd-resolved, `/dev/log` and journald, database sockets and
  an SSH agent beneath `/tmp`. A contract that wants it already has it: a `net:` section refuses every pathname connect it does
  not name.
- *Five named session sockets only.* It left tmux, screen, terminal emulators, editors and the AT-SPI bus reachable.
- *Exceptions taken from the environment* (`$SSH_AUTH_SOCK`, `$TMUX`). An agent that edits the person's shell start-up files
  between runs could point one at the bus; the environment only adds refusals.
- *Let `net.allow` re-admit the bus, X11 or Tego's sockets.* A contract author, or an agent that edits its own contract between
  runs, could reopen exactly the holes the checks depend on. Container sockets are the one exception, explicit by path and
  warned, because an agent that needs one has no other route.
- *Also refuse the SSH-agent sockets.* They do not leave the run cgroup, and git over SSH is common; refusing them would push
  people to drop `net:` sections.
- *Keep every socket beneath `%U/gnupg/`.* gpg-agent's main socket lets a client choose the terminal pinentry draws on and the
  text it shows. gpg signing from inside a run is the cost.
- *Decide only on the reached inode's path.* A hard link or a moved directory gives the socket a path beneath no listed
  directory.
- *Grant only the run's own terminal and nothing else in `/dev/pts`.* Every pty the run allocates is made after the ruleset, so
  `script`, `expect`, a tmux inside the run, Python's `pty`, node-pty and agents' own pty tools would all fail.
- *Open `/dev/pts/<M>` by path after checking the index.* Between the check and the open the run can close the master, and
  devpts hands the lowest free index to the next pty made, perhaps a terminal the person opens.
- *Deny other terminals by ownership.* The agent runs as the same uid as the person.
- *Refuse `/dev/tty*`.* The glob matched serial devices, which embedded and hardware agents use.
- *Rely on Landlock alone.* Pathname unix connects are not mediated below ABI 9 (`RESOLVE_UNIX`), which few kernels have.
- *Refuse everything beneath `$XDG_RUNTIME_DIR/tego`, the run's own directory included.* That directory holds the agent's
  generated `CODEX_HOME`, where the agent may make and use sockets of its own.

## Consequences

- An agent that needed the session bus (desktop notifications through D-Bus, `gio`, a keyring over D-Bus) or another server
  beneath `%U` (audio, a terminal emulator's or editor's remote control, the accessibility bus) is refused, with a reason naming
  the built-in. There is no contract opt-out. The SSH agents of (2) keep working; gpg signing through gpg-agent's main socket
  does not.
- A socket reached through a hard link is refused even when the link is the run's own, outside the run's own directories. A run
  cannot move, link or remove entries in `/tmp/tmux-<uid>` and the other refused directories, so a tmux server inside the run
  uses its own `-S` path or `TMUX_TMPDIR` in a directory of the run's.
- A same-uid server at a path the list does not name, and every abstract name below ABI 6, stays reachable from a contract with
  no `net:` section ("What stays open").
- A pty the run allocates keeps working through `TIOCGPTPEER` and through an `O_NOCTTY` open of its `/dev/pts/<M>` path. Code
  that opens its own slave without `O_NOCTTY`, by a relative path or through a link, is refused with `builtin.other_tty`.
- A device node made under `/dev` after the run starts is not readable until the next run; serial devices present at start stay
  readable and writable.
- An X client in a run that starts its own X server (`xvfb-run`) is expected to keep working through the abstract name its own
  server bound inside the run. This is not yet shown by a test.
- The supervisor now sees bind for contracts with no `net:` section, and `TIOCGPTPEER` and `O_NOCTTY` opens for every contract.
  The build is to measure the overhead and record it, and no budget is relaxed.

## Verification

The implementation is exercised by `TestIntegrationBuiltinRefusals` at tier landlock and
`TestRootBuiltinRefusals` at cgroup and bpflsm in the KVM root suite.
`TestRootBuiltinRefusalsPeer` exercises native datagram decisions without the supervisor.
The following design-level cases describe the intended coverage; the executable matrices combine them:
TestNetlessRunCannotReachSessionBus, TestNetlessRunCannotReachX11 (pathname; abstract at ABI 6 and later, expecting the connect
line `refused` with `builtin.host_ipc` and `net.unix_abstract_scope` true), TestNetlessRunCannotReachTmuxServer, TestNetlessRunCannotReachScreenServer,
TestNetlessRunCannotReachRuntimeDirSocket (by connect and by datagram send), TestNetlessRunCannotReachLinkedHostSocket (with
`/tmp` writable: a symbolic link, a hard link and a moved directory each refused at connect; the move, link and unlink
themselves refused, and at tier landlock recorded as best effort), TestEnvironmentAddsNoException,
TestCredentialAgentSocketStillReachable (the SSH-agent sockets), TestGpgAgentMainSocketRefused, TestAgentCannotConnectControlSocket,
TestAgentCannotReadOtherPty, TestOwnTerminalStillWorks, TestRunOwnPtyStillWorks (`TIOCGPTPEER`, an `O_NOCTTY` open by path,
`posix_openpt` with `/dev/ptmx` a link to `pts/ptmx`, and a race: the master closed while the open is pending gives a refusal,
never another pty), TestSerialDeviceNotRefusedAsTerminal, TestContainerSocketNeedsExplicitAllow.


## Implementation note (2026-11-03, including Round 2 review on 2026-11-04)

The compiler installs all three immutable rule IDs in enforcing contracts. A built-in refusal
wins over `host_sockets: true`, an explicit `net.allow`, filesystem allows and approvals.
The fixed SSH exceptions remove only the built-in floor; ordinary contract permission is still
required. An exact container-daemon socket allow is the documented exception, with its escape
warning. Observe runs enforce none of these rules. Existing record `rule` fields carry the IDs;
no new reason or record minor is introduced.

| Rule | All tiers | Additional root-tier enforcement |
| --- | --- | --- |
| `builtin.host_ipc` | Supervisor frozen connect/bind relay checks copied names, reached inode paths, multiple links and prepared directory identities. Landlock supplies abstract scope from ABI 6, immutable directory write restrictions and existing-FIFO read restrictions. | Cgroup Unix name rows override allows. The LSM/fmod_ret decision plane adds protected parent/name rows and a mandatory native Unix datagram-peer hook, including connected sends and aliases. |
| `builtin.tego_surface` | The same Unix relay protects runtime/control and ledger ask/operator sockets. Frozen TCP relay reserves configured `serve.port` (7433 by default) and legacy port 8484 on local addresses for connect and bind. | Unix name, protected-parent and native peer checks also apply. |
| `builtin.other_tty` | An independent Landlock domain intersects the contract and withholds numeric foreign terminals, including future nodes. The inherited terminal retains READ/WRITE/IOCTL_DEV. Agent `pidfd_getfd` is refused. Both own-PTY APIs use a verified master, TIOCGPTPEER and atomic ADDFD/SEND, without opening a slave pathname. | The same domain and relay apply; there is no per-PTY BPF row. |

Master ownership supplies no filesystem grant. Before delivery the relay verifies the held
slave's device class, inode and kernel path, then checks filesystem read/write permissions,
explicit denies, live blocks and gates. Read/write opens need both permissions. Device
approval completion is unsupported, so fs ask scopes and gate ask ranges cannot deliver a
slave by bypassing an answer. Refusal lines retain the responsible policy rule. Live blocks
are checked again immediately before delivery. Unit tables and landlock/cgroup/bpflsm
integration cover explicit read/write denies and live read/write blocks for both APIs.

FIFO inventory permission failures protect the containing subtree, including listing without
search permission; ENOENT during runtime churn and inventory budget exhaustion also protect
the remaining subtree. Other metadata or
resolution errors fail compilation. Successfully inventoried directories still have the
future outside-created FIFO limit.

The implementation chooses the fail-closed reading on uncertain abstract origins and refuses
root-tier `io_uring: true`, whose operations bypass the relay. Relative host directory
configuration is resolved from the invoking cwd, preserving symlink/.. semantics; an
unplaceable base fails compilation. Unsupported/unreadable bind arguments also fail closed.

Remaining limits include copied-path mutations and admitted/unsupported datagram aliases
without a native decision plane, inherited descriptors, future outside-created FIFOs, abstract
sockets below ABI 6 and host servers at unlisted paths. `builtin.host_ipc/datagram` records the
non-native datagram residual. Full recording supplies notified read refusal attribution;
landlock summary reads can lack a line. Kernel root tiers attribute recorded terminal refusals.
M0 overhead and a logged-in interactive real-client session are not established by these tests.
The Claude examples now use an absolute project-private runtime directory for session sockets;
the repository stand-in exercises startup binding and a Bash tool under both example policies,
with only the model transport redirected to a local server.

On 2026-11-04, installed Claude Code 2.1.318 was also started under both interactive contracts,
using an empty home and no login credentials. `--version` exited 0; `-p --max-turns 1` reached
its expected “Not logged in” result and exited 1. All four runs recorded zero Tego refusals and
verified their chains. This is real-client startup evidence, not a logged-in model/tool session.

The relay also forces `O_NOCTTY` on its own `TIOCGPTPEER` call, even when the caller
omits that flag. The kernel opens the peer in the current task's context
([pty.c](https://github.com/torvalds/linux/blob/v6.17/drivers/tty/pty.c#L589));
without `O_NOCTTY`, a session leader can acquire it as its controlling terminal
([tty_io.c](https://github.com/torvalds/linux/blob/v6.17/drivers/tty/tty_io.c#L2043)).
`TestIntegrationPtyPeerPreservesSession` starts an isolated session leader and verifies
the relay leaves its terminal unset. Without the forced flag, it acquired a terminal
and received SIGHUP on close. The policy matrix also includes peer requests omitting
`O_NOCTTY`. The caller can assign its own controlling terminal explicitly after receiving
an allowed descriptor; the relay never assigns one to the supervisor.


### Round 3 review amendment (2026-11-04): actual Claude socket budget

The Round 2 stand-in's short leaf did not model Claude Code 2.1.318. Its real Linux selector resolves `XDG_RUNTIME_DIR/cc-socks/<pid>.sock` and uses `/tmp/cc-socks-<uid>/<pid>.sock` above 103 bytes, before the kernel's 108-byte `sun_path` capacity. A long project path therefore made the previous templates choose an ungranted shared fallback. Version/unauthenticated print startup alone did not establish socket initialization.

Both interactive contracts now explicitly request `env.set.XDG_RUNTIME_DIR: "%R"`. After harness provisioning, `runtime.configureClaudeSockets` resolves this to the existing private writable `hook-state` directory beneath this run's runtime. The existing inode-checked `fs.harness-state` grant and own-runtime built-in exception cover it; no new filesystem grant, host-IPC exception or record field is introduced. The invoking environment and immutable compiled table remain unchanged. The request requires an unprivileged run with a provisioned Claude harness; an unavailable/dropped harness fails closed. Launch checks the full `cc-socks/9999999.sock` candidate against 103 bytes, including for explicit legacy absolute paths, and refuses before agent start with a clear shorter-runtime fix. Normally the invoking base is `/run/user/<uid>`. Project depth no longer affects the socket address. Shared `/tmp` fallback access stays ungranted.

The stand-in uses the actual PID filename, absolute resolution, byte threshold and shared fallback. Decision tables cover 103/104 bytes, UTF-8 and a seven-digit PID. Both actual templates are exercised under a deliberately long project path: a private PID socket binds/connects and a Bash tool call completes. An app deliberately selecting the fallback is refused, and an old overlong explicit runtime is refused before agent start. This establishes the stand-in socket/tool path, not logged-in real-model interoperability. Real-client socket evidence is recorded below.

Real-client measurement (2026-11-04, installed Claude Code 2.1.318): both unchanged interactive policies initialized a kernel-bound Unix socket beneath this run's `hook-state/cc-socks/<seven-digit pid>.sock`, each 94 bytes, observed with `lstat` and `/proc/net/unix` while the real interactive client was live. Each probe used its own mode-0700 temporary runtime base beneath `/run/user/<uid>`, removed at probe exit, so no normal user runs could be swept. The homes/configs/ledgers were isolated, with no credential environment or login; only presentation/onboarding and project-trust flags were seeded in the private Claude config. Both interfaces reached the prompt and were stopped with SIGINT. Each recorded six refusals: four undeclared helper execs (`dpkg`, `sh`, `ssh`, `sh`) and two undeclared TCP destinations, with no session-socket/fallback refusal. No permission was added for those helpers/destinations. `--version` exited 0 and unauthenticated print reached `Not logged in` (exit 1) under both contracts. This proves real socket initialization and the interactive prompt without a login; it does **not** prove a real model response or real Claude tool execution. Tool execution is established only by the repository stand-in and local model stub.


### CI portability amendment (2026-11-04): configured names and unreachable servers

Immutable entry names come from the configured table, including their final
basename; the existence of a host server or its parent does not select a name.
Existing symlink prefixes still canonicalize parent identities. Prepare, rather
than compilation, pins the first missing component beneath a held ancestor when
a protected parent is absent. This retains coverage if an outside server creates
it later, without broadening an exact SSH/container or own-runtime exception.

For host-server identity pins, ENOENT and EACCES mean absent or unreachable:
there is no present identity to retain, and launch proceeds. The unprivileged
agent has the invoking user's credentials and Landlock only removes access.
The configured name refusal remains. A reachable object is held until teardown
as before. Other errors, including ELOOP, ENOTDIR and descriptor exhaustion, fail
launch; this exception does not relax contractual entries, ledger pins or the
conservative FIFO inventory. Regression tests cover absent and unsearchable
parents, retained reachable identities, unexpected errors, configured aliases,
and names before and after a server's parents are created.

A record-only adoption drops the immutable enforcement state, as observe
compilation does. Retaining that state accidentally installed Unix refusal hooks
on an adoption that promises to record without refusing; the approval-broker
probe must reach the broker and receive its own unauthorized response.

The native peer's link count is read through the selected kernel-memory reader:
probe-read addresses are scalars and cannot be dereferenced as trusted pointers.
The protected-name ancestor walk uses a global subprogram and a bounded
`bpf_loop` callback, following ADR 0024's verifier form, with no increase to the
verified-instruction budget or change to the protected names.

A captured pathname bind whose parent lookup fails completes in the supervisor
with the task-equivalent errno, without handing mutable arguments back. That
lookup error is recorded as supervisor `observed`/`unmatched`, not a policy
allow/refusal or kernel decision. With terminal recording active, its owned
handoff is saved before responding so the unmarked syscall-exit duplicate is
suppressed. The copied spelling is supervisor evidence only. This preserves the
immutable precheck and one result line (ADR 0019's CI portability note).

The plane additionally keeps a resolved target's parent/name guard when a
configured entry is a symlink. Its old inode remains pinned and both the
configured alias and an outside replacement of the resolved target remain
protected. These are runtime plane rows; the compiled entry keeps its configured
name. The native 107-byte replacement-directory regression uses such an alias.
