# Backend capability matrix (spec v0)

Every run records which tier ran and what it could do: `run_start.tier`, and `run_start.capabilities`, one boolean per
row below — this table's column for that tier as the run's own enforcement narrowed it (an unenforced `deny_read`, the
kernel's Landlock ABI), with the rows only the run can answer set from the run: capture from the sources that really
run, the record rows from the record mode (an observe run records what tier 1 records), reads its filter does not see,
and `false` for the rows whose contract fields this binary refuses as not yet supported (both
container rows); `docs/p0/record-ledger.md` §2.2. This table describes the tier and keeps those rows. `status <run>`
prints the run's line with the absent rows by name; the gap report lists what was absent.
The container rows describe the backend design, not accepted contract features. The ask row is true only when
the run starts its authenticated broker and notification supervisor. Safe regular-file open, ordinary TCP and unix
connect approval completion are implemented (a unix connect is relayed as the agent to the place its `net.ask`
`unix:` entry names, whatever name reaches it, supervisor R11c, 2026-10-19; at tiers 2 and 3 an abstract name also needs the run's kernel
to admit that one connect, and is refused `ask-unavailable` before anyone is asked where it cannot), and so is UDP
approval completion (`net.ask` `udp://host:port` or bare `host:port`, supervisor R13d, 2026-10-19: an addressed
datagram or a UDP connect is held and, once approved, relayed from the copies read before the wait; the approval
covers that socket's later datagrams to that destination; at tiers 2 and 3 each relayed operation is admitted by a
one-shot grant the run's `connect4/6` or `sendmsg4/6` takes, and a UDP connect of an `AF_INET6` socket to an IPv4
peer is refused `ask-unavailable` there, since `sendmsg4` decides every later send of such a socket; a `sendmmsg`
batch is not held; no socket of a run that decides datagrams comes to hold a pending frame, which would carry a
relayed or approved datagram to another destination than its line names: `MSG_MORE` on any send, `UDP_CORK`, and a
`sendfile` or `splice` into a UDP, UDP-Lite or raw IP socket are refused `datagram-corked`, decided on the socket itself
(supervisor R13's pending frames, enforce-landlock R11d, 2026-10-20), and one whose socket or descriptor the
supervisor cannot read is refused too, so at tier 1 a process that made itself non-dumpable has every `MSG_MORE` send,
`sendfile` and `splice` refused, a file-to-file copy included (rule `fd-unreadable`, 2026-10-20); at tiers 2 and 3 an approved datagram whose
one-shot credit the kernel left untaken is recorded `observed`, not the person's allow; the disclosed residual is a run
that swaps a descriptor between the supervisor's read of the socket and the kernel's use of it, or a socket handed to
the run already holding a frame, whose later relayed datagrams then join that frame under a line naming their own
address, at tier 1 and the tier-2 fallback, and at every tier for the `models[]` guard's and a gate's relays, which take
no credit); exec approval completion and opaque request inspection remain unsupported and explicitly refuse.
MPTCP approval completion is moot: the socket-family allowlist refuses an MPTCP socket at `socket(2)` under any
`net:` section (ADR 0018 (1)), and an approval is scoped to one ordinary TCP or UDP socket, so a connect on a socket
whose protocol reads otherwise is refused `ask-unavailable` before anyone is asked. A held file read (`fs.ask_read`) is tier 1's alone: its
supervisor is told of every open and completes the read itself, while the root tiers decide a read in the kernel
before any notification could hold it, so `compile` and the launcher refuse `fs.ask_read` there. The HTTP row applies
only to compiled `net.http` policy whose declared forwarder listeners actually started. A capture uprobe does not block a request. Kernel destination rows require measured attachments;
`net.assurance: kernel` additionally requires the strict client socket import/listener filter. The socket-family
row (ADR 0018) is the run's too: under a `net:` section it is true when every socket the run can make is one the
allowlist admits, decided in the kernel on every path (the inherited seccomp arm with io_uring refused, plus
`cgroup/sock_create` at the root tiers, or a plane mode's `socket_create`), and a run with no `net:` section has it
false, since no socket family is refused there (SEMANTICS §1; the unix-only state of ADR 0070 refuses destinations,
not families); `net.assurance: kernel` requires it too. That includes a socket
turned into another family after it is made: `TCP_ULP` is refused by the seccomp arm on `setsockopt(2)` and, at the
root tiers, by `cgroup/setsockopt` on every other path, and the row needs both (ADR 0018 (7)).
The runtime picks the highest tier at or below the machine config's `tier` ceiling unless the contract pins a lower
one. `observe` is a run mode (record only), not a tier.

| Capability | Tier 1 `landlock` (no root) | Tier 2 `cgroup` (root, no boot change) | Tier 3 `bpflsm` (root + `bpf` in the LSM list) |
|---|---|---|---|
| deny file write outside contract | yes (EACCES) | yes (Landlock and fanotify; fanotify refuses with EPERM) | yes, per cgroup, EACCES + reason (decision plane `lsm`; the plane returns 0 or -EACCES only) |
| deny delete, rename, mkdir, mknod | yes (EACCES), per process tree | via Landlock inside the run (per process tree) | yes, per cgroup; a rename or link out of a `deny_read` tree is refused (REFER) |
| deny read of secret paths | by sibling enumeration; unenforced under a writable parent | yes (fanotify, exact paths) | yes, by inode, the nearest entry wins, so a `deny_read` nested in a write entry holds |
| deny exec | by inode (`EXECUTE` on binaries, their loader, listed scripts) | by path (`FAN_OPEN_EXEC_PERM`) | by inode and name per binfmt stage (the file, its directory and its final name) |
| deny network by host:port | yes, supervisor-completed connects (Landlock grants declared TCP ports only) | yes, in-kernel per cgroup, IPv4/IPv6 | yes |
| UDP by destination | best-effort (address read: refused when refused, an admitted one continued and read again) | yes (`cgroup/sendmsg`) | yes (`cgroup/sendmsg`) |
| UDP by port in-kernel | Landlock ABI ≥ 10 only | yes | yes |
| unix sockets | seccomp connect; `RESOLVE_UNIX` on ABI ≥ 9 | `cgroup/connect_unix` on 6.7+, seccomp below | in-kernel, resolved path |
| ask (pause for a human) | yes (seccomp; file reads too, `fs.ask_read`) | yes (no held read: `fs.ask_read` is refused) | yes (no held read: `fs.ask_read` is refused) |
| record exec, write-open, connect | yes (seccomp supervisor, advisory against a hostile process) | yes (eBPF) | yes |
| record reads, mmap, chmod | only with `record: full` (slow) | yes | yes |
| capture model traffic | forwarder | uprobes and forwarder | uprobes and forwarder |
| log allowed actions with the rule matched | seccomp-visible kinds only | all | all |
| adopted containers (daemon-created cgroups) | no: boundary events, API record, gaps | network and record yes; files by fanotify; `ask` refused inside | yes, plus delete/rename per cgroup; `ask` refused inside |
| forwarder HTTP method/path rules (`net.http`) | declared forwarder only | declared forwarder only | declared forwarder only |
| in-tree namespace sandboxes (podman, bwrap) | refused (Landlock topology) | with `containers: rootless` | with `containers: rootless` |
| abstract unix names bound outside the run refused | Landlock ABI ≥ 6 only | Landlock ABI ≥ 6 only (the inherited ruleset) | Landlock ABI ≥ 6 only |
| deny chmod | no: no Landlock ABI has a chmod right | no: fanotify has no permission event for it, nor the inherited ruleset a right | no: `path_chmod` (step B) refuses beneath `deny_write` targets only (enforce-plane R12) |
| TCP destination admission in-kernel | no: supervisor-completed connects | yes (cgroup/connect4 and connect6) | yes (cgroup/connect4 and connect6) |
| Unix destination admission in-kernel | no: supervisor plus ABI-gated pathname backstop | conditional (cgroup/connect_unix and sendmsg_unix, or both plane Unix hooks) | conditional (cgroup/connect_unix and sendmsg_unix, or both plane Unix hooks) |
| exec command rules: argv | best-effort (copied argv; a refusal is exact) | conditional (held by the decision plane's exec pins where doctor's exec pin cell passes; best-effort on the fanotify fallback) | conditional (held by the plane's exec pins where doctor's exec pin cell passes) |
| gate fs open completion | conditional (completed on the object the gate scored by the run's open deputy under `gate.completion: held`, ADR 0041 Stage B; otherwise best-effort: copied pathname, continued; an ask-range score is held, ADR 0008) | conditional (completed on the object the gate scored by the run's open deputy under `gate.completion: held`, ADR 0041 Stage B; otherwise best-effort: copied pathname, continued; an ask-range score is held, ADR 0008) | conditional (completed on the object the gate scored by the run's open deputy under `gate.completion: held`, ADR 0041 Stage B; otherwise best-effort: copied pathname, continued; an ask-range score is held, ADR 0008) |
| gate fs mutation | best-effort (unlink, rename, link, symlink, mkdir, mknod, truncate, chmod, chown and xattr changes, ACLs included, scored on copied names and continued; timestamps are not scored; no kernel layer evaluates a gate predicate) | best-effort (unlink, rename, link, symlink, mkdir, mknod, truncate, chmod, chown and xattr changes, ACLs included, scored on copied names and continued; timestamps are not scored; no kernel layer evaluates a gate predicate) | best-effort (unlink, rename, link, symlink, mkdir, mknod, truncate, chmod, chown and xattr changes, ACLs included, scored on copied names and continued; timestamps are not scored; no kernel layer evaluates a gate predicate) |
| gate exec | best-effort (copied image path and argv, continued; an ask-range score is refused) | conditional (held to the scored image and argv by the plane's exec pins where doctor's exec pin cell passes; otherwise best-effort: copied image path and argv, continued; an ask-range score is refused) | conditional (held to the scored image and argv by the plane's exec pins where doctor's exec pin cell passes; otherwise best-effort: copied image path and argv, continued; an ask-range score is refused) |
| gate net completion | yes on IP-domain sockets (performed on the duplicate with the scored address); addressed unix datagrams, and unix connects with no `net:` section under `host_sockets: true`, best-effort | yes on IP-domain sockets (performed on the duplicate with the scored address); addressed unix datagrams, and unix connects with no `net:` section under `host_sockets: true`, best-effort | yes on IP-domain sockets (performed on the duplicate with the scored address); addressed unix datagrams, and unix connects with no `net:` section under `host_sockets: true`, best-effort |
| protected write targets | best-effort (the supervisor refuses write-opens and mutations on copied pathnames, not chmod, chown or xattr changes; `fs.assurance: kernel` refuses the run) | conditional (a decision plane, `lsm` or `fmod_ret`, by inode, chmod included; best-effort on the fanotify listener, as at tier 1) | yes, by inode (decision plane `lsm`), chmod included (`path_chmod`) |
| sockets outside the net rules' families refused | yes, under a `net:` section (seccomp allowlist on socket(2) and socketpair(2), `TCP_ULP` refused on setsockopt(2); io_uring refused) | yes, under a `net:` section (seccomp allowlist and `TCP_ULP` arm; `cgroup/sock_create` for inet sockets and `cgroup/setsockopt` for `TCP_ULP` on any path; the plane's `socket_create` for every family with a mode) | yes, under a `net:` section (seccomp allowlist and `TCP_ULP` arm; the plane's `socket_create` for every family, io_uring included; `cgroup/sock_create`; `cgroup/setsockopt` for `TCP_ULP` on any path) |
| host daemon sockets refused with no net: section | yes, by the supervisor (every connect relayed; a datagram it cannot relay is best effort below Landlock ABI 9, `host_sockets/datagram`) | best-effort: the supervisor's relay and Landlock as at tier 1, no kernel program of the run (`host_sockets/root-tier`) until the root tiers carry a kernel program for it | best-effort: the supervisor's relay and Landlock as at tier 1, no kernel program of the run (`host_sockets/root-tier`) until the root tiers carry a kernel program for it |
| deny read nested in a write entry | enforced (held), except a moved or hard-linked target | yes (the fanotify listener by path, or a decision plane by inode; the nearest entry wins) | yes, by inode (decision plane `lsm`), the nearest entry wins |
| deny read of a secret made during the run | enforced (held) | conditional: the plane modes' name check (ADR 0043), for a file created directly at a covered name; the fanotify fallback refuses opens and, best effort, mutations; held reads under `fs.reads: held` (ADR 0069) | yes: the plane's name check (ADR 0043), for a file created directly at a covered name beneath each scope; not one reached through a temporary name, a held descriptor or an agent-made symlink; held reads under `fs.reads: held` (ADR 0069) |
| deny read of a nested secret moved or hard-linked | no: a nested target renamed or hard-linked to another name is read by that name (held reads check the object's path and name, not its identity) | conditional (a decision plane refuses a rename or link out of a `deny_read` tree; on the fanotify listener the supervisor refuses one on copied names, best effort) | yes: a rename or link out of a `deny_read` tree is refused (REFER) |
| minimum kernel | upstream tested floor 6.1 (ABI 2); upstream 6.2 truncate; 6.7 TCP ports; 6.12 scopes; 6.15 audit; 7.1 pathname unix; 7.2 UDP ports; ABI 1 unsupported; RHEL 9's 5.14 is a tested matrix row below that floor, run with its backported ABI 6 | upstream tested floor 6.1 (6.7 for `connect_unix`); RHEL 9's 5.14 is a tested matrix row below that floor, run with its backports | upstream tested floor 6.1, whose hook prototypes the plane declares (per-run maps and lsm hooks, ADR 0025); RHEL 9's 5.14 is a tested matrix row below that floor, run with its backported `bpf_loop` and `bpf_rdonly_cast` |
| decision plane | none: the Landlock domain and the seccomp supervisor decide | `lsm` or `fmod_ret`, chosen per boot by doctor's probe; `fanotify` where neither passes | `lsm` (the plane's programs as `lsm/` hooks; needs `bpf` in the LSM list) |

*Amended 2026-10-06:* the minimum-kernel row names RHEL 9's 5.14, which runs every tier with its backports
(docs/ARCHITECTURE.md §14; TIER3-PLAN §7; the `rhel-9` rows of test/vm/README.md, doctor offering bpflsm and kill
tests 1, 2 and 7 passing there); it said 6.1 was the floor of every tier. An upstream kernel below 5.19 has at most Landlock
ABI 1 and is refused (`internal/doctor` `MinLandlockABI`, the `ubuntu-22.04` matrix row).

*Amended 2026-10-16:* the row called RHEL 9's 5.14 a second "tested floor", which `tego doctor`
contradicted on that machine: D1 judges the floor by release version (`internal/doctor` `TestedFloor`, 6.1;
docs/ARCHITECTURE.md §14's "Tested floor: 6.1") and reports "below the tested floor 6.1.0" there, with a "without:"
list naming the Landlock ABIs RHEL backports. The upstream floor stays 6.1 and RHEL 9's 5.14 is named as what it is, a
tested matrix row below that floor whose backports run every tier. Only D1's "below the tested floor" clause is advice:
D1 stays ok at or above `MinKernel` 5.14 (cgroup.kill, SECCOMP_ADDFD_FLAG_SEND) and fails, withholding every tier,
below it; above that line the probes D2-D8 (BTF, cgroup v2, the Landlock ABI, seccomp, the LSM list, the hooks,
fanotify) decide which tiers are offered, and enforcement itself never reads the release. Making D1's floor distribution-aware was
rejected: a floor guessed from a release string (`el9`) states a promise the string cannot carry, and judging it from
the probed Landlock ABI would call any ABI-6 backport tested. `TestTestedFloorMatchesDocs` holds this row and §14 to
`TestedFloor`.

The write-denial row concerns writes outside declared grants. A contract's built-in `deny_write` targets (git
hooks and config, harness settings, shell startup files beneath a write entry) are the protected-write-targets row,
and are refused race-free only by a
kernel decision plane: tier cgroup with `lsm`/`fmod_ret`, or bpflsm. At tier landlock and on tier cgroup's
fanotify listener (including an over-capacity plane's fallback) the seccomp supervisor refuses them on copied
pathnames, best effort: compile warns once per target and the run's `run_start.best_effort` lists
`deny_write/default` (ADR 0041 D1 (a)). A contract that says `fs.assurance: kernel` is refused there before the
child starts instead (exit 125). Narrow `fs.write` to the directories the agent edits to leave the targets out of
any write entry.

A contract's own `fs.deny_write` entries (*added 2026-10-25*, [ADR 0071](../../docs/adr/0071-user-deny-write.md)) are
the same row: they join the built-in targets in one set and are refused by the same mechanisms, race-free by a decision
plane (a hard link made before the run included, to a file entry or to a file beneath a directory entry that compile
found linked, since the plane keys its inode) and best effort below
one, where `run_start.best_effort` lists `fs.deny_write`. Blocked for ordinary commands; not race-free at the no-root
tier. A write entry strictly beneath an entry reopens its subtree at every tier; no write entry reopens a built-in
target.

The three rows from `deny read nested in a write entry` (ADR 0069, appended 2026-10-24, after every earlier row so no
index moves) say what the `deny read of secret paths` row's "unenforced under a writable parent" became. At tier
landlock a `deny_read` target inside a write entry makes the run hold its reads (`fs.reads: auto`, the default): the
open deputy completes every read-capable open and the supervisor refuses one on the object it reached, so the target
holds, and so does a file a deny_read name rule covers that was made during the run (the built-in `.env` names, a
declared glob). A target the agent renames or hard-links to another name and reads there is not caught at tier
landlock (`fs.deny_read.moved`). The static cells say what the tier does under the default; a run's `run_start`
capability line sets `fs.deny_read.nested` and `fs.deny_read.created_later` (and `fs.deny_read`) true only where the
run held its reads and its deputy served it, so `fs.reads: direct`, or a run with no nested target, reads false at
tier landlock. At the root tiers the kernel refuses a nested target itself, and a file made later by ADR 0043's
name entries where the plane's name check decides the run (amended 2026-10-27), and under
`fs.reads: held` by held reads as well.

The five rows from `gate fs open completion` to `protected write targets` (ADR 0041 D7, appended 2026-10-16) say
whether a tier completes a decision the seccomp supervisor takes on copied syscall arguments race-free, on the object
or address it scored (ADR 0041's outcome (A)), or decides it on the copy and continues it, so that a sibling thread can
change what the kernel then acts on (outcome (D), best effort). They describe the tier, not the contract: a run whose
contract has no gate or no built-in target still records them. Which (D) cells a run's own contract has is
`run_start.best_effort`, which compile warns about and `compile --test` names per row. The gate's net row is the
supervisor's relay, so a run records it true only while a started supervisor answers its notifications; the gate's fs
open row is conditional on the contract (*amended 2026-10-17*, ADR 0041 Stage B): a run records it true only when its
contract chose `gate.completion: held` with an fs gate rule that can score to `allow` or above (*amended 2026-10-20*, ADR 0007) and its open deputy started,
so that every such open is held and none is continued, and false otherwise, the deputy's degrade included; the
protected-write-targets row is true exactly where a plane mode decides the run (`run_start.decision_plane` `lsm` or
`fmod_ret`), the reading under which `best_effort` drops `deny_write/default`, for a `tego run` and a boundary
adoption alike (amended 2026-10-16: an adoption claimed it nowhere), and `doctor` answers tier cgroup's
conditional cell from this machine's plane probe. No earlier row moved (R23).

The host-daemon-sockets row (ADR 0070, 2026-10-24) is the run's: `true` when the contract has no `net:` section and
no `host_sockets: true`, the supervisor started and the tier is landlock, where every connect and every addressed
datagram the supervisor can reproduce is performed on its own copy of the socket, behind the abstract-socket scope
(ABI 6) and `RESOLVE_UNIX` (ABI 9); what it continues is `best_effort` `host_sockets/datagram`. At tiers cgroup and
bpflsm the same relay and Landlock carry it, with no kernel program of the run deciding a unix destination for such
a contract, so the row is `false` there and `best_effort` lists `host_sockets/root-tier`, until the root tiers
carry a kernel program for it. A run with a `net:` section has it `false`: the unix sockets row says what it reaches. A
run under the opt-out has it `false` and records `host_sockets: true`.

At tiers cgroup and bpflsm the `deny read of a secret made during the run` row (`fs.deny_read.created_later`) is also
held by ADR 0043's `deny_read` name entries (ported 2026-10-27): a file created after compile at a name
an entry covers (the built-in `.env` family, a declared final-name glob) is refused beneath the entry's scopes by the
plane's name check, whatever its inode. At tier 2 a plane mode decides it; the fanotify fallback refuses the open by
name, and the supervisor refuses a creation, link or rename onto a covered name on its copied pathnames, best effort.
Tier 3 decides it always, with the residuals its cell names (ADR 0043 Residuals). A run without held reads records it
true at a root tier only where the plane's name check decides the run's slot: a plane mode and a table with name
entries, none of whose name-eligible entries (the built-in pair included) a cap or a key collision left out (ADR 0043
D7; compile warns `unenforced` for each one left out, whose later files are not refused); false on the fallback, for a
table with an entry left out, and for a contract with none. A boundary adoption reads it as it reads the plane's
other file rows, and `doctor` answers tier cgroup's conditional cell from the plane probe.

The unix sockets row's implicit admit — a socket under an `fs.write` path reached with no `unix:` entry — holds at
every tier only for a socket the run bound (supervisor R11a), and it needs the kernel's socket diagnostics for
`AF_UNIX` (`CONFIG_UNIX_DIAG`, built in or the loadable `unix_diag` module): without them every such socket is
refused `unix-origin-unread`, and `tego doctor` adds that to the row on such a machine. At tier landlock the
unprivileged supervisor cannot record a socket a non-dumpable process binds (`ssh-agent`), which is refused
`unix-bind-unrecorded` and needs a `unix:` entry; a supervisor with `CAP_SYS_PTRACE` (the root tiers) records it. A
unix name is decided at every tier on the socket it reaches in the agent's own view, a procfs magic link refused
(amended 2026-10-16). A datagram's name is looked up again by the kernel when it is
sent, so a rename or symlink swap by a process of the run in between is a disclosed residual at every tier, as are,
on btrfs or overlayfs, a socket a process in another network namespace binds during one of the run's binds at the
inode number of the run's socket, and `io_uring` connects, sends and binds under `io_uring: true` at tier bpflsm
(supervisor R11a). On btrfs or overlayfs, where a file's superblock and inode number are shared by several
subvolumes' files, the run's socket's file is the one born during one of its binds that no socket outside the run
shares that pair with in the namespace; the run's own socket is refused `unix-origin-unread` while a live foreign
socket shares the pair, or where the filesystem reports no birth time, fail closed, and needs a `unix:` entry then.
A connect there is decided on a list of the namespace's sockets the kernel made in one pass, and refused
`unix-origin-unread` where they do not fit one — some 600 unconnected sockets for a stream or seqpacket connect, and
every socket of the namespace for a datagram socket's connect, which a busy desktop exceeds; a datagram, best effort,
is decided on the whole list, which the run's own socket churn can thin (amended 2026-10-17: a list read across the kernel's datagrams skipped a socket bound throughout).
No bind's name, directory or cwd decides it at any tier (amended 2026-10-17: a bound socket's subvolume
was attributed by its bind's name, and an ordering the run controls admitted a foreign btrfs socket in each round).

A content-selected ELF loader with multiple hardlinks is refused when an enforced `deny_read` directory exists,
because another link could name its unenumerated contents. Use a dedicated single-link loader outside write and
deny paths; this can require de-duplicating an optimized Nix loader. Ordinary single-link loaders and multiple-link
loaders with no ambiguous directory denials still work. Explicit grants and general filesystem aliases retain the
separate boundaries in `docs/p0/enforce-landlock.md` I11; a loader grant no longer silently bypasses this check.

Egress enforcement is destination-based. Declared `net.listen`, `net.ingress` and `net.limits` additionally
provide listener admission, root-tier ingress filtering and run-scoped kernel budgets when their required
measured hooks attach; see [network controls](../../docs/p0/network-controls.md) for the distinct tier guarantees.
System DNS mode retains explicit machine-resolver exceptions on UDP and TCP port 53 without query-content
validation. The cooperating DNS broker is separately authenticated and applies declared name/type policy.
Allowed UDP can carry QUIC. With `net.dns.max_stale`, failed refresh expires last-good address admission at the
configured bound, counted from tego's fixed 60s re-resolution TTL rather than a record TTL; omitted `max_stale` retains historical last-good addresses. Established transports and reply
tracking have separate lifetimes; address expiry does not promise their revocation.

Tier 3 is built through step E. A run gets it (`tego run --tier bpflsm`, or auto as root) where
`bpf` is an active LSM and the decision plane's LSM mode passes doctor's probe: the tier-2 backend with the plane in LSM
mode (docs/p0/enforce-plane.md §2.10). Steps A to D's hooks decide (§2.7, §2.12, §2.14, §2.11: `file_open`,
`bprm_check_security`, `path_rename` with REFER, `path_link`, `path_unlink`, `path_rmdir`, the create and truncate
hooks, `path_chmod` and the attribute hooks for `deny_write` targets, `socket_create`, `mmap_file` and
`file_mprotect`, and below 6.7 `socket_connect` and `socket_sendmsg` for unix names). Step E delegates filesystem decisions
when their loaded hooks and recorders cover the action (§2.13, §2.15); exec decisions and terminal outcomes use the
kernel when both pinned exec-result hooks and the ready recorder provide complete coverage (§2.19). Missing coverage
retains supervisor enforcement and recording. UDP by destination is tier 2's `cgroup/sendmsg` at tier 3 too: the plane's
`socket_sendmsg` decides only `AF_UNIX` datagrams. `deny chmod` is no at every tier: `path_chmod` refuses a mode
change beneath a `deny_write` target only, not under the contract's write rules. The `compile --test` bpflsm
column reads plane rows for filesystem, exec and exec.map actions, with `decision_plane: lsm`, `fs.link`
(`path_link`) and `fs.attr` (the attribute hooks) included (amended 2026-10-16, ADR 0017 (b)), composed with the
Landlock floor every tier keeps (a `#!` script's `EXECUTE`, and from 2026-10-17 a link's and a rename's `REFER`: the
ends' directories and the rights the file would gain, an `exec.allow` directory's `EXECUTE` included; and an unlink's
`REMOVE_*` on its directory). Network
actions, `net.socket` and `net.send` among them, and `exec.anonymous` are policy-model predictions from the predicates
the plane's slot header carries and omit plane provenance; this command does not attach hooks or run the actor.
The `decision plane` row reports the filesystem enforcement mode. Root-tier `run_start` records carry the actual
mode, including the fanotify fallback, from record minor 2 onward. Refusals carry their mode in `decision_plane`
too (`lsm`, `fmod_ret` or `fanotify`; docs/p0/enforce-plane.md §5).
In both plane modes, at tier `cgroup` and tier `bpflsm`, the plane also carries controls that are not rows of
this table (FEATURES E54's 2026-10-05 note; `bpf/decide_control.h`, `decide_socket.h`, `decide_listen.h`):
`ptrace_access_check` in ATTACH mode and `ptrace_traceme` refuse a peer task outside the run and its generation;
`bpf` refuses every `bpf(2)` command a run's task makes; `key_permission`, where the kernel has it, refuses
keyring access unless the contract says `keyring: true`; and, under a `net.listen` section, `socket_bind` (Unix
names) and `socket_listen` admit only the declared listeners. The fanotify fallback has none of them. The `bpf`
and ptrace hooks are a second layer: the seccomp filter's root-tier arm already answers `bpf(2)` with EPERM
(ADR 0033), and every tier's Landlock domain already scopes ptrace (ARCHITECTURE §11).

Race-free ask needs 5.14 (`ADDFD` + `SEND`) and 5.6 (`pidfd_getfd`); older kernels hold and refuse instead of
completing. Rows for ABI 8–11 are untested until a 7.2+ kernel joins `test/vm`. `doctor` prints this table with the
machine's actual values, the highest tier it allows, what the next tier is missing, and the one-line fix.
