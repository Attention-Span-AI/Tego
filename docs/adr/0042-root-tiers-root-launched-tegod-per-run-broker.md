# ADR 0042: tiers 2 and 3 stay root-launched until a named trigger fires; tegod is then a per-run privileged broker started per connection, never a run host

Status: **accepted 2026-10-05.** Built 2026-10-05: (3)(a), (3)(b), (3)(d), (4) and (5)(d), with the documentation; (5)(c)
holds as built (`sys.DropThreadCreds`); (5)(a) and (5)(b) are review rules. Not built: (2)(b) `--run-as` and (2)(c), and
(7), which is built only on a trigger of (6). Amends ADR 0034 ((2)'s 1770 form withdrawn, (5) superseded), ADR 0008,
ADR 0011, ADR 0020 and ADR 0006 (dated notes there). §Implementation notes records where the build departs from the
text. The scope decisions O1 to O6 are: tier 2 and 3 hosts have one administrator (O1); the file-capability path is a
conditioned item (O2); no daemon is built before a trigger fires (O3); a `/run/tego` of mode 1770, a setcap or setuid
copy of tego, a launcher holding a privileged capability without root, and `setuid: true` under sudo without `--run-as`
are refused with exit 125 and a one-line fix (O4; the `setuid: true` refusal is (2)(c), not built); a CI runner reaches tier 2 only where its account is already
root-equivalent (O5); a user who needs a root tier without giving sudo runs on a dedicated host or VM with sudo, or at
tier `landlock` (O6).

## Context

**What tegod was meant to be.**
- A per-host daemon holding "programs, one reader, one writer", checking uid against allowed contracts and max runs with `SO_PEERCRED`.
- ARCHITECTURE sketches it as the run host:
  - §15.7: tegod holds the programs, the ring readers and one ledger writer, and `tego run` is a thin client that
    hands over its seccomp notify fd;
  - §6: "Under `tegod` the daemon owns the lifetime";
  - §7: "`tegod` holds `CAP_SYS_PTRACE`".
- The question was whether in-run containment needs a daemon, under the "anti-cheat" framing: an agent must not be able to disable Tego from inside its own run.

**What changed since then.**
- Containment is built without a daemon. ADR 0033 (3) answers `bpf`, `init_module`, `finit_module`, `delete_module`,
  `kexec_load` and `kexec_file_load` with EPERM at tiers 2 and 3. The plane decides only for cgroups in a run's
  run_set. Control against the machine's own administrator is out of scope.
- Speed and lifetime were measured away. On 6.17, 6.8 and 5.14, an adopt-only tier-2 run under a resident
  holder of the build lock costs the same 136–204 ms as ADR 0022's linger, because bpffs pins outlive processes.
- What remains is one case: root-tier runs for users who are not the host's administrators.

**How tiers 2 and 3 are reached today:**
1. **Only with effective uid 0.** Every root-tier gate checks it:
   - doctor's reach (`internal/doctor/forrun.go:32`, `:102`);
   - the derivation's "root: tier %s needs CAP_BPF, CAP_NET_ADMIN and CAP_SYS_ADMIN" (`derive.go:82`);
   - the system cgroup root (`internal/runtime/cgroup/detect.go:41`) and `helpers.scope` (`helper.go:39`);
   - the credential drop (`internal/runtime/run_child.go:128`).

   `privilegedTarget` (`run_child.go:170`) refuses unless `SUDO_UID` names a non-root account. So a root systemd unit,
   a root cron job or `su -c` is refused (runtime-launch case 36). None of the gates asks whether uid 0 is uid 0 of
   the initial user namespace: under `unshare -r` the real uid is 0 and `SUDO_UID` can be set by the caller.
2. **The drop gives the agent one group.** `sys.DropThreadCreds` (`internal/platform/sys/threadcreds.go:286`) calls
   `setgroups([gid])`: the agent of a sudo run holds its primary gid only, never the administrator's `docker`, `adm`,
   `lxd` or `sudo` groups.
3. **The file-capability copy is not wired.** ADR 0011 and earlier design text describe
   it, but:
   - `privileged_binary` has no consumer outside `pkg/spec/config`, and no test sets a file capability;
   - the run-probe cache refuses the 1770 directory (`internal/doctor/runcache.go:155-161`);
   - on this host bpffs is mounted `mode=700` and the cgroup2 root is root `0555`.

   A copy holding `cap_bpf,cap_perfmon,cap_sys_admin` without `CAP_DAC_OVERRIDE` (rejected by ADR 0034) can therefore
   neither pin under `/sys/fs/bpf` nor `mkdir` `tego.slice`, whatever the gates say.
4. **The root:tego 1770 `/run/tego` form has no launcher to serve, and it exposes root's state.** It comes from
   `packaging/tmpfiles.d/tego.conf`, which is installed by hand. A root launcher accepts it when a group named `tego`
   exists (`hoststate.go` `verifyHost`), and `OpenFile` hands every file root creates there to the group, mode 0660
   (`internal/runtime/hoststate/hoststate.go:156-158`). The shared files are:
   - the slot table's 16-byte records: pid, in-use flag plus epoch, start ticks (`enforce/cgroup/slots.go`). The epoch
     is the gen that ADR 0025's rows carry;
   - the build, timer, ring and library locks.

   Any member can rewrite or lock these without a capability. Worse, `OpenFile` (`hoststate.go:142`) accepts any
   regular file of the name, whoever owns it, so a member can create `slots-<hash>` or a lock before root does and
   root will use it.
5. **`sudo tego` runs the whole launcher as root for the whole run.** ADR 0031: "At tier 2 the whole binary still runs
   as root." That includes the code that parses agent-controlled bytes:

   | Package | Non-test lines |
   |---|---|
   | supervisor memory readers (`internal/runtime/supervisor`) | 10,897 |
   | forwarder | 6,648 |
   | httpstream (with the third-party brotli and zstd decoders) | 2,965 |
   | uprobe | 4,923 |
   | observe | 4,556 |
   | ask broker | 1,118 |
   | DNS broker | 834 |

   The hidden helper commands `__reap`, `__bpf-linger`, `__ring-trim` and `__uprobe-detach` (`cmd/tego/main.go:23-41`)
   act on their argv and inherited descriptors with no check of who started them. The live run directory of a root run
   stays root's until Close (`internal/ledger/handover.go`), so the agent cannot touch the live chain.
6. **`users:` is parsed but nothing honours it.** It parses from every layer (`pkg/spec/config/types.go:212-216`;
   `merge.go:60` uses `setting`, not `etcOnly`), and `tego run` ignores it with a warning
   (`internal/cli/run.go:311`).
7. **Rings are pooled.** ADR 0026 as amended and `enforce/cgroup/rings.go:30-49,187-193`: the 8 lowest slots of a build
   keep their rings after a run (`parkRings`); the next run on the slot drains them and its readers drop records of
   another gen. Removing and re-adding rings costs about 30 ms of RCU grace periods a run on 6.17.

## Decision

**(1) No daemon is built before a trigger.** tegod is not built unless a trigger in (6) fires.

**(2) The privileged path for this release is a root launcher.**

It is `sudo tego run` on a host whose sudo users are its administrators, or a root launch that names the agent's
account ((b)). Users who are not administrators get tier `landlock`. ARCHITECTURE §16, OPERATIONS and SECURITY.md
state this.
- **(a) Granting sudo for tego is granting root**, as membership of the docker group is.
  - The launcher runs as root over inputs the invoker controls: contract and profile files, the per-user layer, and
    the argv of the hidden helpers.
  - A sudoers entry limited to tego is not a boundary Tego supports.
  - A service account never gets one. An agent that escaped its sandbox to that account would inherit root. The one
    stated exception (O5): a runner account that is already root-equivalent, on an
    ephemeral or dedicated runner VM, documented as such.
- **(b) `tego run --run-as <user|uid>` names the agent's account under a root launcher.**
  - It is honoured only when the real and effective uid are 0 in the initial user namespace ((5)(d)). It works with
    or without `SUDO_UID`. The target is never uid 0.
  - It separates two identities that `SUDO_UID` merges today:
    - the **agent account** (the target): the agent runs as its uid with its passwd primary gid as the only group
      ((5)(c)); `HOME`, `USER` and `LOGNAME` are the target's;
    - the **record owner**: the `SUDO_UID` user under sudo (today's ledger root, per-user layer, ask and DNS socket
      owners, and `stop`/`gc` scope), or root under a root unit or cron job with no `SUDO_UID` (ledger in the `/etc`
      layer's `ledger_root`, default `identity.SystemLedgerRoot`, `/var/lib/tego/runs`; `stop` and `status` by root).
  - Nothing is read from the target's tree: its per-user config layer, profiles and home are never consulted. The
    contract, every file it pulls in (`extends:`) and every profile must pass the machine-config file trust rule
    (identity-config R20) with the allowed owners root and, under sudo, the `SUDO_UID` user; never the target. An
    agent that escaped to the target account in an earlier run therefore cannot feed YAML or paths to the next root
    launch.
  - Ledger handover keeps `internal/ledger/handover.go`'s descriptor-relative, `O_NOFOLLOW` discipline.
  - It is runtime-launch case 36's fix. `sudo tego run --run-as <dedicated agent account>` is the recommended way
    to use the privileged path (OPERATIONS), better than running the agent as the administrator.
- **(c) Under sudo without `--run-as`, a contract's `setuid: true` (ADR 0033 (2)) is refused** with exit 125 and
  `[setuid-under-sudo]`, naming `--run-as`. The agent then runs as the administrator on the administrator's terminal
  and session (launch does no `setsid` for the stage), and without `no_new_privs` it could reuse the administrator's
  cached sudo timestamp (Ubuntu's default `timestamp_type=tty`). With `--run-as` the agent's account is one the
  administrator chose, and OPERATIONS says it must have no sudo rights.

**(3) The file-capability copy is not a delivery in this release (O1, O2), and it fails closed.**
- **(a) A launcher that gained privilege without being root is refused; incidental capabilities are cleared.** At the
  top of `main`, before the child-stage and helper dispatch, when the real uid is not 0 of the initial user namespace:
  - **refuse** every command but `version`, with exit 125 and `[privileged-path-unsupported]` naming `sudo tego run`
    and this ADR, when any of these holds:
    - `AT_SECURE` is set (`config.DetectSecureExec`: a file-capability or setuid copy);
    - real and effective uid or gid differ;
    - the permitted, effective or ambient set holds a capability outside the incidental list below.
  - **otherwise clear and continue**: if any capability is held (the incidental list only, typically an inherited
    ambient set such as a unit's `AmbientCapabilities=CAP_NET_BIND_SERVICE`), clear the permitted, effective,
    inheritable and ambient sets (`capset` to empty and `PR_CAP_AMBIENT_CLEAR_ALL`) and continue unprivileged. `run`
    prints one note naming the cleared set. Tier `landlock` runs as it does today.
  - The incidental list is an allowlist, so an unknown capability is refused: `CAP_NET_BIND_SERVICE`,
    `CAP_NET_BROADCAST`, `CAP_NET_RAW`, `CAP_IPC_LOCK`, `CAP_SYS_NICE`, `CAP_WAKE_ALARM`, `CAP_BLOCK_SUSPEND`,
    `CAP_AUDIT_WRITE`, `CAP_LEASE`.
- **(b) A root launcher accepts `/run/tego` only as root 0700.**
  - ADR 0034 (2)'s 1770 form is withdrawn and its shared-group code removed.
  - A 1770 directory fails Prepare with `ErrHostState` and the fix `chmod 0700 /run/tego && chgrp root /run/tego`,
    and remove any tego tmpfiles.d line.
  - `packaging/tmpfiles.d/tego.conf` is deleted. A root launcher creates the directory 0700 itself, and `/run` is
    root's, so nobody else can create the name first.
  - Defence in depth: `hoststate.OpenFile` refuses any file whose `st_uid` is not the effective uid. That closes the
    "create the name first" class even if the directory check ever regresses.
- **(c) "File capability instead of setuid" stays a conditioned item, not dropped.**
  - "Never setuid" holds: sudo now, tegod later.
  - A file-capability copy may come back only for single-administrator hosts, by its own ADR, and only once all of
    these hold:
    - doctor's reach and selection read capabilities, not the euid;
    - the copy can pin and create cgroups without `CAP_DAC_OVERRIDE`;
    - its drop target is defined without `SUDO_UID`;
    - the run-probe cache accepts its state;
    - ADR 0034's two-uid tests and ADR 0020's file-capability kill tests pass.
  - tegod's ADR, when it ships, retires the clause.
- **(d) `privileged_binary` stays parsed and `etcOnly`**, so a machine config that sets it still loads. Setting it
  gives one warning: "privileged_binary is not used in this release; ADR 0042 (3)(c)". It carries (3)(c)'s conditions.

**(4) `users:` is honoured from `/etc/tego/config.yaml` only** (`etcOnly`, as `privileged_binary` is). A per-user or
`$TEGO_CONFIG` layer that sets it gets the "ignored here" warning. Nothing reads it until tegod, and (7)(f) reserves
its meaning.

**(5) Rules for work already planned, and for every privileged path.** (a) and (b) are review rules, not code now;
they keep the split tegod needs cheap. (c) and (d) hold now.
- **(a) Privileged operations pass only plain data and descriptors.**
  - This covers the `internal/runtime/enforce/api` interfaces and every privileged operation added from now on: Prepare, Arm,
    Detach, row grants, net refresh, capture attach and kernel verdict reads.
  - None may call back into the launcher, share a pointer, or assume its caller stays root for the rest of the run.
- **(b) The capture parser must be able to run in another process.** Capture's chunks stay plain values (bytes and
  fixed metadata), so that a pipe can carry them. ADR 0031 (5)'s parser-helper isolation and tegod's
  client both use this seam.
- **(c) A privileged path never widens the agent's groups.** At sudo, `--run-as` and any later split, the agent holds
  its primary gid only (`DropThreadCreds`). Every privileged path has a test that the agent's `id -G` prints its
  primary gid alone.
- **(d) Every "uid 0" gate means uid 0 of the initial user namespace**: real or effective uid 0 and a `uid_map` that is
  the identity map (`0 0 4294967295`). This covers doctor's reach, the derivation, the system cgroup root,
  `helpers.scope`, `privilegedTarget`, `--run-as` and (3)(a). Under `unshare -r` none of them treats the caller as
  root, and `SUDO_UID` is read only by init-namespace root.

**(6) Triggers.** Each pulls a defined slice of (7) forward. S1 is privilege separation of root runs (the launcher split
over a socketpair), S2 is tegod for users who are not administrators, S3 is a record the launching user cannot rewrite.

| Trigger | Fires when | Builds | Until it fires |
|---|---|---|---|
| T1, non-administrator root tiers | A user needs tier 2 or 3 for users or service accounts that must not have root, on a shared host or a CI runner, and a dedicated host or VM with sudo is not acceptable. | S1 and S2 | A dedicated host or VM with sudo, or tier `landlock`. |
| T2, privilege separation | An external review (GAPS B9) or a security finding requires that code parsing agent-controlled bytes not run as root. | ADR 0031 (5)'s capture-parser helper, then S1 | The launcher parses as root under sudo. |
| T3, a record the user cannot rewrite | A user needs a run record or a chain anchor the launching user cannot alter. | S3, on S1 | The ledger is tamper-evident against the agent, not against the launching user (GAPS C9, SECURITY.md). |

**(7) What tegod is when a trigger fires.** These invariants are the fixed boundary. The unit settings, the message
table and the test plans are a provisional design note (appendix); each slice's own ADR fixes them after its
measurements.
- **(a) Shape: a root service started per connection, one instance per run, with no resident run state.**
  - The service manager starts an instance per accepted connection (`Accept=yes` socket activation) running
    `tego __tegod` from the one binary. Where there is no systemd, `tego __tegod --listen` accepts and
    execs one instance per connection by path, never through `/proc/self/exe`, so a replaced binary serves new
    connections.
  - It is an optional add-on. The unit text is embedded in the binary and installed and removed by root with an
    idempotent subcommand; doctor verifies it. Without it the plain path is unchanged.
  - The instance runs in the host's mount namespace and refuses peers outside it ((d)(iv)). Its hardening must not
    change its view of the filesystem (no `ProtectHome=`, `ProtectSystem=`, `PrivateTmp=`, `RootDirectory=`).
- **(b) Ownership: each instance is its run's privileged half.**
  - It owns authorization, the run cgroup in RUN-IDENTITY's system layout, the slot, the rows, the rings and their
    relay ((d)(i)), Arm, capture attach, grants and Detach.
  - **Reaping is ADR 0020's, unchanged.** After Prepare the instance starts `tego __reap` for the run exactly as the
    sudo launcher does: with a pidfd of the instance, the run-directory descriptor the client handed over at Open, and
    the verified `/run/tego` descriptor, in `tego.slice/tego-reap.slice/reap-<id>.scope` with `oom_score_adj`
    -1000. One lifetime model, ADR 0020's tests reused, at the ~6 MB per live run that ADR already accepts. When the
    instance dies (OOM, `kill -9`, `systemctl kill`, a bug), its reaper kills the run cgroup, appends `run_end
    reason=orphaned` through the descriptor, removes the cgroup and purges the run's links, rows and slot.
  - The kernel-state purge does not depend on the ledger: the reaper always kills and purges, and appends `run_end`
    only if the ledger has none (the client, if alive, writes its own when the connection drops). Root appends to an
    existing user-owned events file through the descriptor and creates nothing under the ledger root.
  - When the client dies, the instance sees the hangup, ends the run with `stop_grace`, Detaches and purges. When
    the instance gets SIGTERM (`systemctl stop`, shutdown), it does the same. `tego stop` of a brokered run signals the
    client (same uid); a wedged client is SIGKILLed, which closes the connection and ends the run.
  - Helpers it spawns (`__reap`, `__bpf-linger`, `__ring-trim`, `__uprobe-detach`) go to their own scopes
    (`tego-reap.slice`, `helpers.scope`), never the instance unit's cgroup, so ending the unit kills none of them and
    ADR 0022's linger outlives the instance.
  - `max_runs` is held by per-uid quota locks the reaper inherits ((f)), so an orphan counts until it is reaped.
  - Host-wide state does not move: `/run/tego` (root 0700), the bpffs pins, the linger timer and their flock
    protocols (ADRs 0020, 0022, 0026, 0034), shared unchanged with sudo launchers.
- **(c) The client is the unprivileged `tego run`, and it stays the agent's parent.** It does:
  - its own compile, for its Landlock and seccomp layers;
  - the child stage, the supervisor, the ask and DNS brokers and the forwarder;
  - the ring readers, on relayed bytes, and the capture parsers;
  - the ledger, in the user's `ledger_root` (ADR 0004 unchanged);
  - the terminal and signals.
- **(d) Invariants.**
  - **(i) No BPF object, BPF descriptor or cgroup file reaches the client.** The instance acts only on objects it made
    for this connection, plus the client's stopped stage for placement: it checks by pidfd that the stage is the
    peer's child, has the peer's uid and is in no run, and after the move checks again (the pidfd is alive and is the
    process in the run cgroup), as systemd's `PidRef` does.
    - **Ring bytes are relayed, not ring descriptors handed over.** The instance consumes the run's rings by `mmap`
      and `epoll` and writes their records, unparsed, to a pipe per ring that it hands to the client. It reads only
      the kernel's ringbuf header (length, busy and discard bits) and the BPF-written record header (gen), and drops
      any record of another gen, so ADR 0026's pool stays as it is: a pooled ring never leaves root, no run can read
      another's (another uid's capture plaintext included), and no ring memory outlives a run in a user's hands.
      Backpressure is a slow reader's today: the pipe fills, the ring fills, the kernel counts drops.
    - [measured, this decision, 2026-10-05, host 6.17, `GOMAXPROCS=4`] A relay process copying from memory to a
      1 MiB pipe moved 2.3–2.8 GB/s in 16 KiB writes (6.2–7.1 µs CPU each, about 0.1 µs per 256-byte record when
      batched per drain) and 1.5 M unbatched 256-byte records a second (0.67 µs CPU each).
  - **(ii) It takes no policy decision from the client.**
    - Rows come from its own compile of the contract, in a child: either an administrator's file named by `users:`,
      or the peer's bytes in a sealed memfd. The child is exec'd as root with an empty environment, then drops to the
      peer's uid and the gids from `SO_PEERGROUPS` (the groups at connect time) and clears its capabilities. The
      credential change leaves it non-dumpable (the kernel sets `suid_dumpable`, 0 by default) and it also sets
      `PR_SET_DUMPABLE` 0, so the peer can neither ptrace it nor write its memory at any Yama setting. Every path the
      contract names resolves with the peer's own rights.
    - The client sends a digest of its own canonical rule table in Open, and the instance refuses a mismatch. That
      catches a compile race, compiler skew and namespace confusion that the checks below miss.
    - The real argument: rows only narrow below DAC, and the tier and capture ceilings are applied by the instance from
      the `users:` entry, never taken from the compile output. A peer that subverted its own compile could only loosen
      its own run, which `"*"` already lets it do by writing the contract.
    - Addresses for declared hosts come from its own resolution, and the client's DNS broker serves them.
    - Identities come from the kernel. A grant sent after an approval must match an ask entry of the compiled contract.
  - **(iii) It reads no agent memory and parses no ring payload.** It parses two kinds of agent-reachable bytes:
    - the ELF of a library a verified run member maps, opened through `/proc/<pid>/map_files` ((e)), which a root
      launcher parses today too (fuzzed by `FuzzReadBinary`);
    - its compile child's output, a canonical rule table decoded strictly as untrusted input.
  - **(iv) The peer shares the instance's world.** At Open the instance compares, through the peer's pidfd, the
    peer's user, mount, pid, net and cgroup namespace ids and its root directory (`/proc/<pid>/root` against `/`) with
    its own, and refuses any difference with `[peer-namespace]` and a doctor sentence. That refuses a rootless or
    rootful container with the socket bind-mounted, a chroot, and a systemd unit with `PrivateTmp=`, `ProtectHome=`,
    `RootDirectory=` or its own namespaces: their agents do not live in the filesystem and network the instance
    compiles for. A later ADR may compile after `setns(pidfd, CLONE_NEWNS)` instead.
  - **(v) Root is not a client.** A peer of uid 0 is refused: root uses `tego run` directly. Since (iv) puts every
    peer in the instance's user namespace, uid 0 here is init-namespace root, and refusing it also refuses a rootful
    container that has the socket mounted.
  - **(vi) Agents cannot be clients.**
    - A peer whose cgroup is under `tego.slice` or in a run_set is refused (tier-2 and tier-3 runs).
    - That check does not cover a tier-1 run, whose agent lives in the user's delegated subtree and can move within
      it. So the tier-1 supervisor and the client's own seccomp layer refuse `connect` to a sockaddr that resolves to
      the tegod socket's inode. A test connects from inside a tier-1 run.
    - The connection descriptor is `O_CLOEXEC` and never reaches the stage. A test asserts that the agent finds no
      tegod socket in `/proc/self/fd`.
    - Nested runs go through the outer client; tegod routes no asks.
  - **(vii) Peer identity is checked per entry form and on every message.**
    - Socket activation and `--listen`: `SO_PEERCRED` at accept; `SO_PEERPIDFD` on Linux 6.5 and later, else
      `pidfd_open` followed by a re-check of the uid and of the connection (5.14, 6.1).
    - Socketpair (S1's sudo split): `SO_PEERCRED` reports the credentials at `socketpair()` time, which are root's. So
      the root launcher passes the expected uid, primary gid and client pid to the instance at start, and the instance
      takes identity from that, never from `SO_PEERCRED`.
    - Every message's `SCM_CREDENTIALS` must match the pid, uid and gid established at the start. A leaked descriptor
      in another process fails the pid check.
  - **(viii) The client is outside every run and unreachable from inside one.** S1 moves the supervisor, the
    forwarder and the live ledger from root into the user's uid, which is also the agent's uid in a tegod run. That
    trades a uid boundary for the run's confinement, and the invariant says what the confinement must give:
    - the agent cannot signal, ptrace, `process_vm_readv`/`writev`, `pidfd_getfd` or open `/proc/<client>/mem`,
      `environ` or `fd` of the client;
    - the agent cannot write the live run directory.

    Mechanisms: the client sets `PR_SET_DUMPABLE` 0 once the stage has handed over its listener (the stage stays
    dumpable, which `pidfd_getfd` needs, `launch/child.go:220`); the plane's scoped `ptrace_access_check`
    (`decide_control.h`) must be live for a split or brokered run, else the run is refused; signals are scoped by
    Landlock ABI 6 and, below it, by the supervisor's own signal scope (`signalScopeTest`); the run directory lies
    outside every `fs.write` (E12) and gets a plane deny-write row. A separate per-run uid for the client was
    considered and rejected (Options, D14). OpenSSH's precedent is the narrower one: its pre-auth child runs as a
    dedicated unprivileged uid, not as the attacker's.
  - **(ix) Groups.** In a tegod run the agent inherits the client's groups, which are the user's own, as at tier
    `landlock`; that is no widening relative to the user. At sudo and `--run-as`, (5)(c).
  - **(x) Plane modes only.** No fanotify fallback (that listener needs `CAP_SYS_ADMIN` in the client and does not
    scale: 85 µs an open at 2 runs, 1.3 ms at 8), no `setuid: true` (ADR 0033 (2)), and no privileged
    commands until an ADR grants them through `users:`.
  - **(xi) The capability set is enumerated and tested, not assumed.** Candidates: `CAP_BPF`, `CAP_PERFMON`,
    `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`; `CAP_DAC_OVERRIDE` (mkdir under the root 0555 cgroup2 root and pin under a
    `mode=700` bpffs: Context 3); `CAP_SYS_PTRACE` (a peer's or run member's namespaces and `/proc/<pid>/maps` and
    `map_files` of another uid); `CAP_CHECKPOINT_RESTORE` or `CAP_SYS_ADMIN` for `map_files`; `CAP_SETUID` and
    `CAP_SETGID` for the compile child; `CAP_KILL`; `CAP_SYS_RESOURCE` (the reaper's `oom_score_adj`); `CAP_MAC_ADMIN`
    where a kernel requires it for BPF LSM. S2 removes each in turn and checks that a named step fails, and that the
    full set passes.
  - **(xii) A brokered run hits doctor's run-probe cache.** The cache key (`internal/doctor/runcache.go`) includes the
    raw `/proc/thread-self/cgroup`, which is unique per `Accept=yes` instance, so every brokered run would miss and pay
    D7 (7.8 s on 6.17) and leave a new `doctor-probe-*.json` in `/run/tego`. The instance keys by its unit template
    (the instance leaf stripped), the number of probe files is bounded, a warm-up oneshot after the socket unit fills
    the entry at boot and after an upgrade, and Open's deadline tolerates a 6–17 s cold probe.
- **(e) Protocol.** One `SOCK_SEQPACKET` connection per run, a fixed header and strict bodies, descriptors by
  `SCM_RIGHTS` with an exact count and a type check per message. Any unknown type, field, descriptor or version closes
  the connection and the run ends (fail closed). Hello carries a protocol version and the client's `bpf_hash`, checked
  separately (a userspace-only change is not a ring-layout mismatch); a mismatch prints both values and which side to
  upgrade. **AttachCapture carries no path**: it names a run member's pid and a mapping start address. The instance
  checks that the pid is in this run's cgroup, opens the library through `/proc/<pid>/map_files/<range>` (the inode
  the member actually mapped), and attaches only probes whose emission is routed in-kernel to this run's ring (ADR
  0026). Root therefore never opens or parses a file the peer named, nor probes an inode the run never mapped.
- **(f) Authorization.**
  - `users:` (`/etc` only) maps an account to `{contracts, max_runs, tier, capture}`. Entries carry the name and the
    uid, both checked against passwd at connect, so a deleted account's entry does not pass to a reused uid; doctor
    warns about an entry whose uid has no passwd row. Groups through `SO_PEERGROUPS` come later.
  - `contracts` lists agent names whose files the administrator keeps in a root-owned directory, named by an
    `/etc`-only key and trust-checked like the machine config. Every file they pull in is resolved there too.
  - `"*"` admits the peer's own contracts. It then authorizes use of the host's kernel resources, not a contract, which
    is why `tier` and `capture` are ceilings: the plane costs every host process about 200–300 ns per open (ADR 0022),
    and capture probes on a shared libssl about 2.4 µs per TLS call.
  - `max_runs` is the quota: the instance takes the first free of `quota-<uid>-<k>` (k < max_runs) in `/run/tego` by
    non-blocking `LOCK_EX` and the reaper inherits it. The files carry no content, so binaries of two versions agree
    on them, and there are at most max_runs per uid. The service manager's connection limits are a safety net above
    it.
  - No entry means no run. uid 0 is refused ((d)(v)).
- **(g) What it replaces.** tegod replaces the file-capability copy as the route for users who are not
  administrators. It does not replace sudo, which stays the single-binary path.
- **(h) Out of scope until their own ADRs:** a ledger written by root; routed asks; `CAP_SYS_PTRACE` asks (a non-dumpable
  target of a non-root client records `ask-unreadable`, as at tier `landlock`); SELinux and AppArmor policy for the
  socket (the guests load no policy).

**(8) Cold start is not a reason for a daemon.** A warm build is ADR 0022's linger. Boot-time priming stays off by default and is never
counted toward `cold.bootfirst.ms`.

What runs as root, by deployment:

| | sudo today | sudo with `--run-as` | tegod run (T1) |
|---|---|---|---|
| **Runs as root** | all of `tego run`: config, compile, Prepare, supervisor, forwarder, capture parsers, observe, ask and DNS brokers, ledger writer; the reaper | the same | the instance: authorization, cgroup, slot, rows, rings and their relay, Arm, capture attach, Detach; its compile child drops to the peer; the reaper |
| **Runs as the user** | the agent (as the administrator, primary gid only) | the agent, as the dedicated account | `tego run` (all the rest) and the agent |
| **Host state** | `/run/tego` 0700, bpffs pins, flock protocols | the same | the same files and protocols, plus per-uid quota locks |
| **Lifetime owner** | the launcher plus `__reap` | the same | the instance plus `__reap` |

## Why

[measured; ADR 0022's Option C] No speed or lifetime case remains for a daemon:
- an adopt-only tier-2 run under a resident holder costs the same 136–204 ms as the linger;
- bpffs pins already outlive processes.

[measured, ADR 0022's 2026-09-30 note, enforce-plane §10.1; 6.17, 4 vCPUs]
- With the build kept, a plane run costs 90 ms.
- After `gc --builds` it costs 1.8 s (fmod_ret), 2.1 s (bpflsm) and 3.3 s (LSM mode).
- The first plane run of a boot pays 5.9–17 s more, because doctor's D7 loads every program in 7.8 s.

A resident process could hide only these cold costs, and only by staying warm, which `bpf.linger` already does. The
remaining cold misses come from loading the programs, which a resident process would not remove.

[documented, ADR 0033] The "anti-cheat" goal, that an agent cannot disable Tego from inside its
run, is met without a daemon: the root-tier filter refuses `bpf`, module loading and kexec, and the plane decides only
for governed runs. Anti-root control is out of scope.

[documented] A single binary stays the install, and the launcher stays the owner of the run's cgroup and asks. A
mandatory daemon would contradict that. An optional, socket-activated one does not, because the plain path keeps working
on its own.

[read, code] The only route to tiers 2 and 3 today is effective uid 0 (Context 1). The
file-capability copy cannot work as designed: five euid gates refuse it, `privileged_binary` is unused, and without
`CAP_DAC_OVERRIDE` it can neither pin under a `mode=700` bpffs nor create `tego.slice` under a root `0555` cgroup2
root. The 1770 form shares root's slot table and locks with a group and lets members create those names first
(Context 4). Keeping either "as single-user only" would keep an advertised path that cannot run and a state form that
only weakens root's. That is why O1 and O2 were chosen.

[read, `pkg/spec/config/secure.go`] `AT_SECURE` is the kernel's own "privilege gained by exec" bit: set by file
capabilities and setuid, not by inherited ambient capabilities. Refusing on it, on a uid/gid mismatch and on any
non-incidental capability, while clearing an incidental ambient set, stops the copy and keeps a unit with
`AmbientCapabilities=CAP_NET_BIND_SERVICE` working at tier `landlock`, as it does today.

[documented, ADR 0031; code `cmd/tego/main.go:23-41`, `internal/runtime/reap.go` `ReapMain`] `sudo tego` is root for
the whole run, and its hidden helpers trust their argv. A restricted sudoers entry is therefore not a boundary. Docker
documents the same for its group: "only trusted users should be allowed to control your Docker daemon", and the docker
group is root-equivalent (docs.docker.com/engine/security, read 2026-10-05). Saying so plainly costs nothing and
prevents the one dangerous configuration: a service account with `sudo tego`, which an escaped agent would inherit.
`--run-as` gives the safe form of the same deployment, and reading nothing from the target's tree stops the confused
deputy in which an escaped agent feeds the next root launch.

[documented, external] Privileged helpers that inherit a user's process context are a recurring source of local root:
CVE-2020-5291 (bubblewrap, setuid mode with `--userns2`, fixed in 0.4.1); CVE-2022-31214 (firejail's setuid `--join`,
DSA-5167); CVE-2023-29403 (the Go runtime under setuid or setgid, fixed in 1.19.10 and 1.20.5). systemd's `run0`
(v256; LWN 971745) starts the privileged process from the service manager instead of inheriting the caller's
context. OpenSSH's privilege separation (Provos, Friedl and Honeyman, USENIX Security 2003) pairs a privileged monitor
with an unprivileged child per connection; note that its pre-auth child runs as a dedicated uid, not as the
attacker's, which is why (7)(d)(viii) states what the confinement must give in place of that uid boundary. These
precedents point to a narrow privileged process started clean, beside an unprivileged process that does the parsing,
joined by a socket with peer credentials. A capability-bearing copy of a 66.8k-line launcher points the other way.

[documented, systemd.socket(5), systemd 257 on this host] `Accept=yes` spawns a service instance per connection and
passes it only the connection. `MaxConnections=` defaults to 64; `MaxConnectionsPerSource=` counts per source UID on
AF_UNIX. The man page recommends `Accept=no` "for performance reasons", for per-request connections; tegod's
connection lasts a whole run, and a run already costs 85–136 ms warm.

[measured; 2026-10-05, host 6.17, systemd 257 as the user] Per-run start cost:
- through PID 1's `Accept=yes` path (`systemd --user`, `SOCK_SEQPACKET`, connect until EOF, 40 runs twice): `/usr/bin/true` p50 6.8–7.0 ms; the 19 MB tego binary (`version`) p50 9.5–10.1 ms, p90
  10.6–17 ms, the first of a series 17–26 ms, one 234 ms outlier on a loaded host;
- through `systemd-socket-activate --accept --seqpacket`: 3.6–4.0 ms in 9 of 10 runs; this is a lower
  bound, not the budget.

So the instance's start alone spends about 10 ms, before its compile child and its compile, which runs twice (once in
the client for Landlock and seccomp, once in the child for rows). The budget is therefore 30 ms p50 added to a warm
start, measured on the system manager with a 10,000-file tree, and only after (7)(d)(xii) makes brokered runs hit the
run-probe cache. The service manager's poll limit admits about 75–90 accepts a second, so 300 runs
started together wait seconds; Open's deadline allows for it.

[inference, from ADRs 0020, 0022, 0026 and 0034] Per-connection instances beat a resident daemon here:
- The per-run processes already coordinate through flock in `/run/tego` and bpffs, and that coordination is tested
  (ADR 0020's concurrent reapers, ADR 0022's timer, the two-launcher build-lock tests). An instance per run reuses all
  of it, and is today's root launcher's privileged half plus ADR 0020's reaper, unchanged.
- A resident daemon would need a second lifetime model (ARCHITECTURE §6's "the daemon owns the lifetime"), recovery of
  every run when it restarts, version skew between an old daemon and new clients, and in-memory state shared by every
  user's requests.
- The instance form gets crash isolation (one run, reaped by its own reaper), clean upgrades (new connections exec the
  new binary; two builds coexist as §6 allows) and a clean exec context from PID 1 (the `run0` lesson).

[documented, ADR 0026, ADR 0004, ADR 0014's open item; measured above] ARCHITECTURE §15.7's run host is the wrong
shape: it would put every user's ring parsing, capture decoding (third-party brotli and zstd) and ledger writing into
one long-lived root process. ADR 0026 gives each run its own rings and ADR 0004 keeps the ledger per user. Relaying
ring bytes keeps the parsing in the user's process at about 0.1 µs a record, without handing the user a BPF object.

[documented, external] `SO_PEERPIDFD` and `SCM_PIDFD` exist since Linux 6.5, which closes the pid-reuse race on peer
identity (dbus merge request 398; LWN 937009). polkit brings D-Bus and a JavaScript rules engine into the authorization
path; see CVE-2021-4034 (pkexec) and CVE-2021-3560 (polkitd).

## Security argument

**The now-part only narrows.**
- (3)(a) refuses a launcher that gained a near-root capability set by exec, and strips incidental inherited capabilities
  before any code path uses them. It stops nothing that works: no capability copy can reach tier 2 today (Context 3),
  and an ambient-capability unit keeps running at tier `landlock`.
- (3)(b) removes group-writable root state and the window in which a member can create root's file names first; the
  `st_uid` check in `OpenFile` closes that class independently.
- (4) stops any layer but `/etc` from ever reading as authorization.
- (5)(c) and (5)(d) pin today's single-group drop and make every uid-0 gate mean init-namespace root.

Decided, not built: (2)(b) would move the agent off the administrator's account onto a dedicated one and read nothing
from that account, and (2)(c) would close the cached-sudo-timestamp route of a `setuid: true` agent running as the
administrator.

(3)(b) stops one working setup: a root launcher on a host where an administrator installed the 1770 line by hand. That
setup gained nothing from the group form, and its refusal names a one-line fix. Once built, (2)(c) stops `setuid: true`
under plain sudo, and `--run-as` restores it safely.

**The later part shrinks what runs as root, and states what it trades.**
- In a tegod run, root executes only the instance: `enforce/cgroup` (11,980 lines), `runtime/cgroup` (1,830),
  hoststate (215), the BPF bindings, doctor's probes, the ring relay (header reads and copies), and the decoder,
  authorization and placement that S1 and S2 add. Today `sudo` runs all 66,838 non-test runtime lines as root.
- The roughly 30,000 lines that parse agent-controlled bytes, `pkg/spec` with the policy compiler (22,280 lines) and
  the ledger writer (5,493) run as the user.
- The trade: those components then share the agent's uid. (7)(d)(viii) makes the agent's inability to reach the client
  and the live run directory an invariant with named mechanisms and tests, instead of assuming it.

**Confused deputy (the Docker lesson).**
- The instance acts only on objects it minted for this connection and on the verified stage ((7)(d)(i)); it opens no
  file the peer names ((7)(e)).
- Rows come from its own compile with the peer's rights; ceilings come from the entry ((7)(d)(ii)).
- The peer shares its namespaces and is not root ((7)(d)(iv), (v)).
- So membership of the socket group grants exactly the `users:` entry, never root's reach.
- An agent cannot reach the socket as a client ((7)(d)(vi)); peer identity is fixed per form and checked per message
  ((7)(d)(vii)).

**Failure modes.**
- **An instance that dies** leaves its run to its reaper, which kills and purges it within ADR 0020's bound. No other
  run is affected. If the reaper is also killed (both OOM-killed), the run stays fail-closed (links and rows pinned) and
  the next root `tego gc` collects it, as in ADR 0020's stated residual. S2 decides whether every instance also runs a
  bounded sweep of dead runs at start (D16).
- **A connection flood** is bounded by the quota locks, then by the service manager's connection limits and poll limit.
  A connection refused by the service manager reaches the client as EOF before the first reply, which the client maps
  to "tegod busy or unavailable" with a distinct exit code and no retry loop.

## Options considered

**Chosen:**
- daemonless root launchers for this release, with honest documentation, and `--run-as` as decided (not built);
- the file-capability path and the group state failing closed, subject to O1 and O2;
- `users:` read from `/etc` only;
- named triggers;
- tegod's invariants fixed now, as per-connection privileged instances beside an unprivileged client, with ring bytes
  relayed and ADR 0020's reaper per run;
- a dedicated host or VM with sudo, and `--run-as` once it is built, as the default answer before T1 fires.

**Rejected:**

| Option | Reason |
|---|---|
| (A as researched) Keep the daemon as the later route and harden or document the file-capability path as single-user. | The path cannot run (five euid gates; DAC on bpffs and the cgroup root). Its 1770 state only weakens root's. Failing closed is the honest form of A (O1, O2). |
| (B) A minimal resident tegod now. | Now: nothing requires it, and a required one breaks the single-binary install. Later: the resident form loses to per-connection instances (second lifetime model, restart and upgrade recovery, cross-user in-memory state). |
| (D1) polkit over D-Bus for authorization. | D-Bus and a JavaScript rules engine in the authorization path (CVE-2021-4034, CVE-2021-3560). Breaks the one static binary. |
| (D2) E63a: `users:` enforced inside the sudo launcher. | The invoker is root; a restricted sudoers entry is not a boundary ((2)(a)); quotas among administrators protect nothing. |
| (D3) User authorization inside the file-capability launcher. | Not wired; no DAC rights on bpffs or the cgroup root; shared-group state; a near-root capability set on the whole launcher (the CVE class above). |
| (D4) Wire the single-user file-capability copy. | The same blockers. On a single-administrator host, sudo with `--run-as` gives the same thing. |
| (D5) Privilege separation of sudo runs now, OpenSSH-style. | It is S1, on T2. The external review decides; a T2 finding gets the parser helper first. |
| (D6) A setuid helper. | ARCHITECTURE §16 says never setuid; the CVE class above. |
| (D7) BPF tokens (Linux 6.9+). | Absent on the 5.14, 6.1 and 6.8 rows. They hand program loading to the user's own process, the opposite of a narrow broker. |
| (D8) ARCHITECTURE §15.7's run host. | Puts every user's agent-facing parsing in one long-lived root process. |
| (D9) tegod to hide cold start. | The measurement above; linger already keeps builds warm. |
| (D10) Root tegod runs in each instance's `Delegate=yes` cgroup. | A second layout to sweep, breaks the per-agent slice. Reconsidered only with where a privileged launcher's cgroups live, which is decided before S1. |
| (D11) A check in the hidden helpers against direct invocation via sudo. | Would imply that a restricted sudoers entry is a supported boundary. It is not. |
| (D12) A non-root tegod with its own directory (ADR 0034 (5)). | It could neither pin nor create cgroups. tegod is root. |
| (D13) Hand ring descriptors to the client, consumed by `mmap` and `epoll`. | ADR 0026's pool keeps a slot's rings for its next run, which may be another uid's: a client that keeps its descriptor or mapping reads that run, capture plaintext included. Even fresh per-run rings leave memory charged to root's memcg alive for as long as the user holds a descriptor, past `max_runs` and `bpf.ring_budget`, and drop the pool's ~30 ms saving. Relaying costs about 0.1 µs a record (measured). It also removes the need for an unprivileged ring consumer and its five-kernel spike. |
| (D14) Run the client half under a separate per-run uid (OpenSSH's pre-auth model). | The client must `pidfd_getfd` from the stage, which needs ptrace access to the agent's uid: a different uid would need `CAP_SYS_PTRACE` in the client. It also needs a uid allocator and a ledger handover to the user. (7)(d)(viii) gets the property by invariant and tests instead. |
| (D15) A lease file per run plus "any root sweep" for crashed instances. | On a host whose runs all go through tegod no root sweep may ever run; no sweeper enumerates leases; lease contents would need to be root-written argv for a reaper; lock files are never unlinked (ADR 0034 (3)). ADR 0020's per-run reaper already solves it. |
| (D16) A host-wide root sweeper (`tego gc --host`) on a timer. | Workable, but a second recovery path with its own record format. Not the primary path; root's `tego gc` stays the backstop for a reaper killed with its instance, and S2 may add a bounded start-of-instance sweep. |
| (D17) `TriggerLimitBurst=0` on the socket. | The poll limit, not the trigger limit, throttles a flood first (600 and 2,000 simultaneous connects left the socket active either way); removing a limit buys nothing. |
| (D18) Root needs no `users:` entry. | A rootful container with the socket mounted is uid 0 in the init namespace. Root has `tego run`. |
| (D19) Refusing every launcher with any capability and a non-zero real uid. | Breaks a unit with `AmbientCapabilities=CAP_NET_BIND_SERVICE` that runs tier `landlock` today, and doctor, compile, status and events with it. |
| (D20) Refuse peers that have `no_new_privs` set (it marks every Tego agent). | Also refuses ordinary hardened units (`NoNewPrivileges=yes`), a common setting. (7)(d)(vi)'s cgroup and connect checks cover agents. |

## Consequence

- **Root tiers in this release need an administrator.** Tiers 2 and 3 run on hosts the user administers:
  `sudo tego run`, and `--run-as` a dedicated agent account once it is built. Everyone else gets tier `landlock`.
- **The docs stop advertising a path that does not run** (the file-capability copy), say what sudo is, and say that
  the ledger is tamper-evident against the agent, not against the launching user (GAPS C9), until T3.
- **Migration** (OPERATIONS): a host that installed `packaging/tmpfiles.d/tego.conf`
  must `chmod 0700 /run/tego && chgrp root /run/tego` and remove the line; a `setcap` copy gets exit 125 naming
  `sudo tego run`. The refusal of `setuid: true` under sudo and `--run-as` are not in this release.
- **Privilege separation is a deferred condition.** A long-running root unit keeps the whole launcher as root for days;
  the external review decides T2 with that in view.
- **ARCHITECTURE §15.7's one-writer-per-host design is withdrawn.** ADRs 0004 and 0026 stand.

## Implementation notes

*2026-10-05:* (2)(a), (3), (4) and (5) built. Where the build departs from the text above, and why:

- **(5)(d)'s helper lives in `pkg/spec/config`, not `internal/platform/sys`.** `config.InitialUserNamespace`
  (`/proc/self/uid_map` is the one line `0 0 4294967295`, read once per process) and `config.InitNSRoot` (effective
  uid 0 and that) sit beside `InvokingUID` and `DetectSecureExec`: `InvokingUID` must apply the rule to `SUDO_UID`,
  and `pkg/spec` imports nothing from `internal` (the depguard rule spec-is-pure). The gates call it from there:
  doctor's reach and scope (`forrun.go`, `report.go`, so the derivation's `root:` line), the bpffs reads of `doctor`
  and `gc`, `cgroup.Detect` and `helpers.scope` (identity-config R19, R19a).
- **The credential drop still applies to any effective uid 0.** `run_child.go`'s gate asks whether the agent would
  run as uid 0, not whether the launcher is root of the host; narrowing it to `InitNSRoot` would let an agent run
  as uid 0 of a child namespace undropped. Under `unshare -r` the drop has no target, because `SUDO_UID` is not read
  there, and the run is refused as case 36 refuses a root unit.
- **(3)(a) reads the capability sets only in the initial user namespace.** Under `unshare -r` or in a rootless
  container uid 0 holds every capability of its own namespace and none over the host's BPF, cgroup2 root or
  `/run/tego`. Read there, the allowlist would refuse every command, doctor and tier `landlock` included, which
  contradicts this ADR's own `TestUnshareRootIsNotRoot` ("`unshare -r tego doctor` reports no root reach") and
  gains nothing the (5)(d) gates do not already refuse. In a child namespace only `AT_SECURE` and an id mismatch
  refuse.
  *2026-10-06:* only a child namespace shown by a uid map that was read skips the sets. The guard
  took `config.InitialUserNamespace`'s fail-closed `false` for an unreadable map as a child namespace, so a
  non-root launcher with no `/proc` (a chroot or minimal container, where `AT_SECURE` still comes from `unix.Auxv`)
  holding an inherited `cap_sys_admin` or `cap_bpf` was let through with it. `config.CurrentUserNamespace` now
  answers initial, child or unknown; the guard reads the sets of an unknown namespace as of the initial one, and
  does not take its uid 0 for root, while `InitNSRoot` and `InvokingUID` still take it as not root.
- **Clearing reaches every thread.** Capabilities are per thread and the Go runtime holds several threads before
  `main`, so the clearing is `sys.ClearProcessCapabilities`: `capset` to empty and `PR_CAP_AMBIENT_CLEAR_ALL` through
  `syscall.AllThreadsSyscall`. A cgo build (the `-race` test builds) cannot reach cgo's threads, gets `ENOTSUP`, and
  is refused rather than half-cleared; the shipped binary is `CGO_ENABLED=0`. The ambient set is read with
  `PR_CAP_AMBIENT_IS_SET`, and only when permitted and inheritable share a capability (the kernel keeps ambient
  within both). Root of the initial namespace returns after the ids and the uid map, so a root launcher's stages and
  helpers read no more. [measured, 2026-10-05, 6.17, unprivileged] the check costs 7.3 µs a call after the uid map's
  one read, on every tego process.
- **An inheritable set alone is neither refused nor cleared.** (3)(a) says "clear when any capability is held"; the
  inheritable set holds nothing usable (it grants only through file capabilities that name the same ones), and an
  Ubuntu desktop session hands every process `cap_wake_alarm` there (measured), so clearing
  it would print the note and pay for a clear on every command. "Held" is the permitted, effective and ambient sets;
  once one of those is cleared, all four are emptied. The child stage empties the inheritable set before the agent's
  exec in any case (`sys.ClearCapabilities`).
- **`AT_SECURE` is read from the runtime's copy of the auxiliary vector.** `config.DetectSecureExec` read
  `/proc/self/auxv`, which refuses its own process once a file-capability or setuid exec has made it non-dumpable
  (`EACCES`, found by `TestFileCapabilityCopyIsRefused` in the guest): it failed in exactly the case it exists for.
  It now reads `unix.Auxv` (the vector the Go runtime kept at start) and the file only as a fallback; a read that
  fails still refuses.
- **The `tegotesthooks` override of `hoststate.Path` is not built.** `Path` is a constant at about a dozen call sites,
  including the argv protocol of the detached helpers (`linger.go`, `rings.go`, `uprobe/shared.go`), so overriding it
  is its own change. `TestRootLauncherRefusesGroupHostState` instead changes the guest's (or the throwaway runner's)
  own `/run/tego` and `/etc/group` and restores both.
  *2026-10-06:* the aim that a `VM_HOST=sudo` run never touches the real host,
  is kept by confining the test instead. It skips, saying why, unless `TEGO_DISPOSABLE_HOST` is set, which
  `test/vm/root-suites.sh` sets in every KVM guest (`scripts/coverage.sh` too) and, under `VM_HOST=sudo`, only on a
  GitHub Actions runner (`GITHUB_ACTIONS=true`, which sudo would drop) or when its caller sets it; a bare
  `GITHUB_ACTIONS=true` also counts. The root-must-pass entry still runs in the guest and in CI's root-suites job; on
  a developer's machine the skip is not in `root-skips.txt`, so that run fails rather than pass without it.
  `/etc/group` is edited the way the shadow tools do it: a file in `/etc` with the old one's mode and owner, synced
  and renamed over it, for the added line and for its removal, so a killed test never leaves the database
  truncated. The removal takes out only the added line, so an edit another process made meanwhile survives. An
  existing `tego` group with members is refused before anything changes, since `/run/tego` root:tego 1770 would
  hand those members root's host state for the test's duration. A killed run on a disposable host can still leave
  `/run/tego` 1770 and the added line; the override of `Path` stays its own change.
- **The file-capability copy is tested on a private tmpfs, not `/vm`.** `TestFileCapabilityCopyIsRefused` mounts a
  tmpfs without `nosuid` in its temporary directory and writes `security.capability` there with `unix.Setxattr`, so
  it runs the same in the KVM guest (whose `/tmp` is `nosuid`) and as root on a runner.
- **ADR 0034's doctor host-state row** is still not added; the refusal carries `hoststate.Fix`.

Tests: `TestIdentityUIDMap`, `TestReadUserNamespace`, `TestInitNSRootIsEffectiveRootInTheInitialNamespace`,
`TestInvokingUID` (`pkg/spec/config`); `TestUsersIsTheAdministrators`, `TestPrivilegedBinary`; `TestVerifyHost`,
`TestOpenFileRefusesAFileAnotherUIDOwns` (`internal/runtime/hoststate`); `TestAmbientCapabilitiesMatchesTheStatusLine`,
`TestClearProcessCapabilitiesReachesEveryThread` (`internal/platform/sys`); `TestPrivilegeActionTable`,
`TestGuardPrivilegeRefusesWithTheCode` (`internal/cli`); and as root in the KVM guest (root-must-pass):
`TestUnshareRootIsNotRoot`, `TestRootLauncherRefusesGroupHostState`, `TestFileCapabilityCopyIsRefused`,
`TestAmbientIncidentalCapabilityRunsLandlock` (`internal/runtime`).

*Amended 2026-11-11 (wording):* in Decision (2)(a), "an agent that escaped its sandbox" means an agent that escaped
its run, the processes Tego holds to the contract. Tego does not hide the machine (README, Known limits). The
decision is unchanged.
