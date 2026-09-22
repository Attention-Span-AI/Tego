# ADR 0008: approvals are completed by the supervisor, never by CONTINUE

Status: accepted 2026-09-21.
Amended by ADR 0041 (accepted 2026-10-05: a held open is completed by an in-run open deputy rather than a supervisor thread, after its Stage B prototype meets its budget; Stage B is not built, so this decision's supervisor-thread completion stands until it is; as of 2026-10-16 Stage B is built as the contract opt-in `gate.completion: held`, per ADR 0041's Status, and without that opt-in the supervisor-thread completion still stands).
Amended by ADR 0042 (accepted 2026-10-05): the Consequence's tegod capability.
Amended in part by ADR 0047 (accepted 2026-10-20, built 2026-10-27): unlink, rmdir, mkdir, rename, symlink and link inside an `fs.ask` scope are asked, not refused, and an approved one is made by the supervisor's identity-adopting thread on the directories it pinned; a rename or link across entries is refused `EXDEV` as unsupported.
Amended in part by ADR 0044 (accepted 2026-10-16, not built): an approved exec is the one approval completed by `CONTINUE`, and only with the supervisor's `PTRACE_SEIZE` in place first, so the kernel's own facts are compared at the exec stop before the first instruction and a mismatch is killed.
Decision: approved opens are completed with `SECCOMP_IOCTL_NOTIF_ADDFD` + `SECCOMP_ADDFD_FLAG_SEND` (Linux 5.14+); approved connects are performed by the supervisor on a `pidfd_getfd` duplicate of the target's socket (Linux 5.6+); every target-memory read is bracketed by `SECCOMP_IOCTL_NOTIF_ID_VALID`. `SECCOMP_USER_NOTIF_FLAG_CONTINUE` is used only to hand non-ask syscalls back to the kernel's own checks.
Why: the man page states CONTINUE has a time-of-check/time-of-use race and must not be used for security decisions; ADDFD and the shared open file description remove the window.
Consequence: the ask supervisor needs `PTRACE_MODE_ATTACH_REALCREDS` over the target (an ancestor of the same uid satisfies Yama scope 1; `tegod` needs `CAP_SYS_PTRACE`). Minimum kernel for race-free connect approval is 5.6, for atomic open approval 5.14; older kernels fall back to hold-and-refuse.

Amended 2026-09-21: the supervisor performs approved opens on a locked thread that first adopts the target's identity (fsuid/fsgid/groups/umask from `/proc/<pid>/status`, dirfd and cwd resolved under `/proc/<pid>/root` with `RESOLVE_IN_ROOT`, the target's flags verbatim); a root launcher never opens with root credentials. `ask` entries carry no Landlock or kernel rights of their own (compiled as refused); modifications other than open inside an `fs.ask` directory are refused, not asked. Supervisor-completed connects make host-level deny an unprivileged-tier property (Landlock grants declared ports only; every allowed connect is completed by the supervisor). Yama: `PR_SET_CHILD_SUBREAPER` keeps daemonized descendants in scope; non-dumpable targets are served only by a `CAP_SYS_PTRACE` supervisor, else `ask-unreadable` and a gap. io_uring is refused (`ENOSYS`) unless `io_uring: true` in a root tier; `openat2` is refused so callers fall back to `openat`.

Amended 2026-09-21 (second): in tier 1 Landlock handles `CONNECT_TCP` and each declared port becomes a rule, which sees the port and never the host (*corrected 2026-11-01*: this said "no port rules at all", which `enforce/landlock/net.go` does not do; below ABI 4 there is no rule and the supervisor decides alone); every allowed connect is performed by the supervisor on the duplicate, so an in-kernel connect from inside the run to an undeclared port is refused. TCP Fast Open sends with an address are decided like connects. `ptrace_access_check` in tier 3 scopes both modes by run tree, matching Landlock's implicit scoping.

Note: the 5.6 and 5.14 numbers here are the minimums for the race-free paths only; the authoritative mechanism-minimum table and the tested floor (6.1) are in ARCHITECTURE §14.

Amended 2026-10-04: local approvals now use a bounded per-run Unix seqpacket broker, per-packet kernel credentials, a nonce handshake and retained peer pidfds. The administrative caller must be outside the governed cgroup and its descendants. The CLI retains a verified launcher/lock identity and checks the broker peer. Ask and answer records are accepted before grant; ledger append failure ends the run.

Amended 2026-10-05: the broker's socket is `<ledger run dir>/ask.sock` (`ask.SocketName`), bound through an `O_NOFOLLOW` descriptor of the run directory, mode 0600 and chowned to the invoking UID when the launcher runs as root; the CLI dials the same path. It is not under `$XDG_RUNTIME_DIR` or `/run/tego` (ADR 0034 does not cover it), as a runtime comment claimed. A replaced pathname cannot forge an approval: the CLI checks the broker peer's SO_PEERCRED pid against the verified launcher and the broker authenticates every packet.

Filesystem scopes remain separate from ordinary grants. Current approvals cover regular-file write-open/create, pin both the prelaunch scope and actual target/parent, preserve the target identity and umask, and use atomic ADDFD+SEND. Other mutations, special files and O_TMPFILE refuse. Root-tier TCP connects use one exact socket-cookie/destination credit consumed by the connect hook; no run-wide allow is installed. First-write mode is a bounded loopback delivery relay, so sends may buffer and the visible peer is the relay. Request mode requires authenticated fixed-model HTTP capture, complete bounded body parsing before the ask, and body/credential-sensitive retry coalescing with a single upstream dispatch. UDP/Unix/raw/MPTCP approval, opaque TLS/CONNECT/WebSocket request inspection, setuid and io_uring combinations are unavailable.

The implementation follows the kernel's [atomic ADDFD completion and copied-argument requirements](https://docs.kernel.org/userspace-api/seccomp_filter.html#userspace-notification) and [Unix packet credential semantics](https://man7.org/linux/man-pages/man7/unix.7.html). These mechanism references do not replace actual supported-tier acceptance tests.

Atomic ADDFD+SEND does not make the preceding supervisor open transactional. After approval, a create/truncate effect can complete before notification withdrawal or delivery failure. A separate human-authorized filesystem event records `operation_completed`, `fd_delivered` and, when delivery is no longer observable, `result_unknown`; an approved answer alone never claims target success. There is no rollback promise for the approved filesystem effect.

*Amended 2026-10-16:* the ADDFD|SEND ioctl runs with every signal blocked on the
supervisor's thread (`sys.SeccompNotifAddfdSend`). The kernel mishandles a signal that reaches the supervisor while
the ioctl waits for the target to take the descriptor (`seccomp_notify_addfd`, through 6.17 at least): it has already
marked the notification answered and woken the target, takes the queued descriptor back and returns `-ERESTARTSYS`,
so the target's open returns 0, a descriptor nobody delivered, and the ioctl, restarted by the Go runtime's
`SA_RESTART`, fails `ENOENT` (or `EINPROGRESS`). One approved open in about 2,800 came back to an agent that way,
which its write met as `EBADF`, while the ledger said `result_unknown`; a signal storm against the answering thread
turned half of 3,000 deliveries into 0 before the fix and none after (`TestAddfdSendUnderASignalStorm`). End to end, a `tego run` at tier `landlock` of 3,000 write-opens under one standing approval failed 1 on the agent before the fix with no signal added, and 211 with every tego thread flooded with SIGURG; after it, 0 of 3,000 and 0 of 5,000 under the flood (`TestIntegrationApprovedOpensSurviveASignalStorm`, 1,000 opens: 96 failed before). Rejected:
retrying the ioctl (the reply is already gone), plain ADDFD followed by `NOTIF_SEND` of the number (restart-safe, but a
target interrupted between the two keeps a descriptor it never asked for), and a dedicated non-Go thread (no cgo in
this build). SIGKILL, SIGSTOP, a cgroup freeze or a ptrace interrupt of tego itself still reach the thread; an
`EINPROGRESS` they leave is `sys.ErrNotifReplyLost`, and the loop then answers nothing again and records the open as
performed, not delivered, `result_unknown`.

*Amended 2026-10-05 (ADR 0042 (7)(d)(iii), (xi)):* the Consequence's "`tegod` needs `CAP_SYS_PTRACE`" becomes:
tegod reads no agent memory; it holds `CAP_SYS_PTRACE` only to read a peer's or a run member's namespaces and
`/proc/<pid>/map_files`. Asks stay the client's supervisor's, as at tier `landlock`; a non-dumpable target of a
non-root client records `ask-unreadable`.

*Amended 2026-10-16 ([ADR 0041](0041-race-free-supervisor-decisions.md) Stage B):* the header's "Stage B is not built"
no longer holds. Stage B is built as the contract opt-in `gate.completion: held`: under it a gate-raised open (the ask
range on an open the floor allows) is pinned, approved and opened by the run's open deputy, inside the run's domain and
cgroup, and delivered by `ADDFD|SEND`. An `fs.ask` or `fs.ask_read` approval, and an alternate, keep this decision's
supervisor-thread completion under the target's credentials: those scopes carry no kernel right of the run's by design,
so the run's own context would refuse them (ADR 0041's Step 8 note says why the deputy does not take them). A person's
alternate for a held gate ask is taken as on any hold, and completed the same way, reopened as the target's
credentials. Without the key nothing here changed.

*Amended 2026-10-19 (supervisor R11c):* an approved unix connect is completed as this decision completes a
TCP one, on the `pidfd_getfd` duplicate of the target's socket, and by R11's relay: the name is resolved as the
target, on a thread holding its credentials, and connected by the inode reached, which must lie at the place the
`net.ask` `unix:` entry names. Nothing is connected before the approval, and `CONTINUE` decides none. At tiers 2 and 3
a pathname relay is admitted by the run's programs as every R11 relay is, by the relay's `/proc/self/fd/<n>` name from
the launcher's cgroup; an abstract name, connected with the target's own bytes, needs a one-connect kernel grant, and
is refused before the prompt where the run cannot install one.
*Design note, 2026-10-19:* **a pathname scope is a place, and what
a person approves is that place.** The place is the entry's path resolved once when the run starts — from its deepest
existing directory, every symlink followed, a symlink whose target the run makes later followed to it
(`agent.ResolveUnixPlace`, which compile uses for `compile --test` too). Whether a connect is asked is decided by the
place its name reaches in the target's view, walked as the relay walks it, never by its spelling, and the approval
admits the relay's connect at that place only: one decision, on one model, before and after the person. A name that
reaches another place is decided there as every connect is (R11a): the run's own socket under a hard link or after a
rename is the write entry's, and a socket the run did not bind is refused `unix-foreign`. Earlier versions held a
stronger property — the scope's socket is never admitted under any name, even when the run bound it — and
tracked the run's socket across renames and links to hold it (marks taken at binds and decisions, the kernel's bound
name, `unix-ask-scope-unread` for what could not be read); each fix left another branch, a rename with no
decision in between defeated it, and it guarded nothing, since the run reaches a server of its own under any name by
binding a fresh socket. Rejected, with that tracking: trapping every rename and link to complete it, matching the
scope by spelling with the place as a second check (the two disagreed), and asking
about the run's socket under every name. Disclosed: a scope inside a write entry is only as fixed as that directory —
the agent can rename or link another socket of the same filesystem onto the place, and the person approves the place
the target names.
*Implementation note, 2026-10-19:* the place is resolved as the
kernel resolves a path, component by component: `agent.ResolveUnixPlace` lets the kernel's own walk resolve the
deepest existing prefix and takes each component below it in turn, so a `..` in a dangling link's target, or one the
walk meets after a symlink (a declared path's own `..` is cleaned lexically by compile first),
applies after the symlink before it is followed (it cleaned the joined target lexically, and a scope at
`s -> sub/../x.sock` with `sub` a symlink was placed beside `s`, where an approval then connected another socket). A
connect whose last component is a symlink that leads nowhere yet is placed where it leads, as a scope is, and so is
asked when that is a scope's place (it was placed at the link, and the scope's own name was admitted by the write
entry around it unasked). Rejected: refusing `..` in a scope's path or target (the kernel accepts it, and a refusal
would differ from what `compile --test` and the run's lookup do), and matching such a dangling final link by spelling
only (an agent-made link to the same place would still go unasked).
*Implementation note, 2026-10-19:* `agent.ResolveUnixPlace` no
longer asks a resolver about each prefix: it walks the path from the root one name at a time, one readlink per name
(a symlink followed whether or not its target exists, a `..` popping the name before it), bounded at 1024 names and
40 links, because the supervisor also places agent-made names (a connect whose socket or directory is missing) and
resolving every prefix of each link's target with `filepath.EvalSymlinks` cost tens of seconds per connect on a planted
chain. A name past the bound is no scope's, decided where it leads. A relative name whose directory is missing is placed
from the cwd and the name uncleaned. A `..` written in the declared path is cleaned lexically by compile, as in every
contract path; only a `..` the walk meets (in a link's target, or in a connect's name) is applied after the symlink
before it. Rejected: a dirfd walk (`openat` per name, O(1) each; a new kernel interface and fake for what the bound
already caps at tens of milliseconds), compile's `resolveProbe` for the existing prefix (still one probe per prefix,
quadratic in the names), refusing a `..` in a declared `unix:` path (a relative `../app.sock` from a subdirectory is
ordinary, and every other contract path is cleaned the same way; the person is shown the cleaned path).
*Implementation note, 2026-10-19:* the "tens of milliseconds" above
held only while the directories each readlink walks stay plain: an agent's thread that turned a name the walk had kept
(nothing there yet) into a symlink made every later readlink of the placement follow it, up to 40 links of `PATH_MAX`
bytes each, 1.17 s for one placement in a deterministic race and 266 ms worst case with a real racing thread. Each
read is now `agent.ReadPlaceLink` (the supervisor's `PlaceLink`): `openat2` of the name's directory with
`RESOLVE_NO_SYMLINKS`, then `readlinkat` of the name, so a read never follows a link the walk did not choose; a
directory that became a symlink fails `ELOOP` and the placement ends, not placed (the connect is no scope's and is
decided where it leads, as one past the bound is). Rejected: the dirfd walk again (a held descriptor per directory,
up to 1024 open per placement on each of four workers, and a new walker seam and fake, where one `openat2` per read
restores the bound with the readlink seam kept), and a wall-clock or total-work budget (a placement's answer would
then depend on the machine's load, where the verdict must be deterministic). Where `openat2` is refused (`ENOSYS` or
`EPERM`: a kernel before 5.6, a seccomp filter such as a governed run's own) the read falls back to the whole path's
readlink, whose cost under such a race is disclosed: bounded only by the constants (1024 reads through up to 40 links
each, 1.46 s measured). With `openat2`, one placement is at most 1024 reads through plain directories, raced or not:
35 to 56 ms measured for a path 1100 directories deep, so "tens of milliseconds" holds again. An `EINTR` read is
retried, as `os.Readlink` retried it, and one still interrupted ends the placement, not placed, as does any read
failing with anything but `EINVAL`, `ENOENT` or `ENOTDIR`, the three answers that say the name is no link (an `EMFILE` read kept a symlink as a plain directory). Keeping `EACCES` as a plain name was
rejected: this process's permission is not the task's, so the read says nothing about the name.
An approved connect the run's kernel refuses after all (its one-second grant lapsed) is not recorded as the person's
allow: a TCP connect's line is the kernel's refusal its breadcrumb names, or `observed`, and an abstract unix name's
`observed`.

*Amended 2026-10-19 (supervisor R13d):* an approved UDP datagram is completed as this decision completes a
connect: the datagram is held, its address and payload are copied before the wait, and an approval sends those copies
on the `pidfd_getfd` duplicate of the target's socket, never by `CONTINUE`, which would have the kernel read both
again after a sibling thread could rewrite them; a UDP connect is held and relayed as a TCP one. The approval is scoped
to that socket and that destination: the socket's later datagrams to it are relayed unasked (each still from its own
copies and with its own line), as the stream a TCP approval opens flows unasked, and another socket is asked again.
Rejected: asking for every datagram (a resolver's retries or a QUIC handshake would each wait for a person, with
`--always` the only way through, which widens to every socket of the run); a run-wide grant for the destination (it
would admit sockets nobody approved and outlive the approval's object); a kernel-side standing grant per socket (rows
that must be cleared when the socket closes, which no hook here sees, where a one-shot credit per relayed datagram is
cleared by the relay that made it). At tiers 2 and 3 each relayed datagram or connect takes a one-shot credit in
`tego_connect_approvals` keyed as the hook reads it (UDP, the socket's cookie, the slot's gen), which `sendmsg4/6` or
`connect4/6` consumes; a UDP connect of an `AF_INET6` socket to an IPv4 peer is refused before the prompt there, since
`sendmsg4` decides each of that socket's later sends and an approved connect would carry none.

*Implementation note, 2026-10-19:* three limits of the
socket-scoped approval. (1) A relayed datagram is sent from its copies, but a UDP socket holding a pending frame
(`MSG_MORE`, `UDP_CORK`) appends it to that frame before the kernel reads the address, so the approved bytes went to
the frame's destination under a line naming the approved one. The supervisor now refuses, `datagram-corked`, a relay
with `MSG_MORE` or on a corked socket (read before the prompt and again before the relay) and `MSG_MORE` on any
addressed UDP datagram under a `net:` section, so no frame forms from a send it sees; a frame left by a send it never
sees (an unaddressed `sendto`, `sendfile`) is a disclosed residual (supervisor R13). Rejected: trapping
`setsockopt(UDP_CORK)` in the filter (the cork read covers a cork that stays set, and a cork cleared flushes the frame);
reading `SIOCOUTQ` to infer a pending frame (it also counts datagrams awaiting transmit completion, so a busy socket's
approved datagrams would be refused at random). (2) Every relayed operation's one-shot credit has the same key for a
socket and destination, and the map takes one row per key, so two threads' approved datagrams refused each other; the
supervisor now serializes the grant, relay and revoke of one key (`grantOnce`, a wait of at most a second). Rejected:
a counted credit (a BPF change, and a revoke would still have to tell its credit from another's). (3) Under a net gate
the socket's approval is kept with the gate's verdict, score and rule, so a datagram scored otherwise is asked again,
as the broker never keeps a scored answer. Rejected: asking for every gated datagram (rejected above for all datagrams).

*Implementation note, 2026-10-19:* (1) A UDP-Lite socket
sends through `udp_sendmsg` and keeps its pending frames, but its line's proto is `raw`, so the pending-frame refusal
skipped it; it now counts as UDP there (`udpFramed`). (2) An unaddressed `sendmsg` or `sendmmsg` with `MSG_MORE` under a
`net:` section with no gate or guard was continued unread, so the claim that no frame forms from a send the supervisor
sees was false; it is now refused `datagram-corked` too, the socket resolved only for a call carrying the flag. The
residual is a frame from a send the filter never notifies (`send`, an unaddressed `sendto`, `sendfile`, `splice`).
Rejected: refusing a relayed or approved datagram on a connected UDP socket (`getpeername` on the duplicate), proposed to
narrow that residual: a frame an unseen `send(MSG_MORE)` left on a connected socket survives
`connect(AF_UNSPEC)`, after which `getpeername` reports no peer and the next addressed datagram still joins the frame
(host probe on 6.17, loopback: the second datagram reached the first's peer, appended), so the check would cost a
syscall per relay and refuse legitimate sends without closing the residual. (3) `tego_unix_approvals` keys its row by
the socket's cookie alone, the name being the value, so `grantOnce`'s per-name key let two approved connects of one
socket to two abstract names write one row; the unix key is now the cookie alone.

*Design note, 2026-10-20:* earlier fixes patched cases of two models that were wrong, and each left the next
case. Both are replaced.

(1) *Pending frames are a property of the socket, kept where they form.* Before, each send path asked whether its own
call could start or join a frame from what that path had at hand: a `sendmmsg` batch took the socket's protocol from
its first address, so a unix one let a UDP batch with `MSG_MORE` through (an approved datagram then went
to the frame's port under a line naming the approved one) and an IP one refused a unix socket's batch; UDP-Lite and the
unaddressed sends were added one round at a time; a raw IP socket, which corks with `MSG_MORE` too, never was; and a
`send()`, a `sendfile` or `splice` onto the socket, and a `UDP_CORK` under continued datagrams, were left open. Now a run
that decides datagrams (`agent.RuleTable.DecidesDatagrams`: a `net:` section, a guarded `models[]` endpoint or a net
gate) keeps one invariant: no socket comes to hold a frame through a syscall of the run. It is decided where a frame
forms, on the socket's own `SO_TYPE`, `SO_PROTOCOL` and `SO_DOMAIN` read from the duplicate, never on an address the
call carries, and a socket that can hold a frame is an IP datagram socket other than a ping socket (UDP, UDP-Lite, or a
protocol that could not be read) or a raw IP one, one whose domain cannot be read counting as one: (a) a `sendto`,
`sendmsg` or `sendmmsg` whose flags register carries `MSG_MORE` is refused `datagram-corked` before anything about its
destination is decided (supervisor `refusesFrame`), and the filter now notifies a `sendto` with no address that carries
the flag; (b) `setsockopt(UDP_CORK)` at `SOL_UDP` or `SOL_UDPLITE` is notified and refused, whatever the value; (c)
`sendfile` and `splice` are notified and refused into such a socket (enforce-landlock R11d). The filter's arms and the
refusal read the one predicate, so the two layers cannot disagree on a run. A datagram the supervisor sends itself, a
relay or an approval, meets one precondition (`frameFree`: no `MSG_MORE`, and on UDP a cork read as clear), which now
covers only a socket the run was handed corked. At tiers 2 and 3 an approved datagram's line is then held to the
kernel's own answer: `sendmsg4/6` takes the credit only for that socket's datagram to that destination, and
`udp_sendmsg`/`udpv6_sendmsg` append to a pending frame before they run the hook, so a credit left in the map after a
relay the kernel answered with success means the hook never took it (the datagram joined a frame, or, rarely, a
refresh admitted its destination by an ordinary row during the wait, which no breadcrumb tells apart), and its line is
`observed`, the person's, under the scope's rule, never an allow of a destination the bytes may not have reached.
*Residual, disclosed:* a run that
swaps a descriptor between the supervisor's read of the socket and the kernel's use of the number (a `dup2` of a UDP
socket over a TCP one while a `MSG_MORE` send of the TCP one is held) forms a frame no layer sees, at tier 1, at the
tier-2 fallback and, for the relays that take no credit (the `models[]` guard's, a gate's), at every tier; so does a
socket handed to the run holding a `MSG_MORE` frame its creator left; a later relayed datagram then joins that frame,
whose destination the run admitted, under a line naming the relayed address. A run that declares `io_uring: true`
(neither `ask` nor `gate` compiles with it) sends through its ring unseen.

Rejected: refusing `MSG_MORE` on every send in the filter, which is race-free on the register alone but fails a TCP
send that carries the flag as a hint, and leaves `sendfile` and `splice`; reading `SIOCOUTQ` before each relay, with or
without a bounded wait for it to drain (it counts datagrams still awaiting transmit completion, so a busy socket's relays
would be refused at random or, under the guard's QUIC relay, wait on every datagram); refusing
`UDP_CORK` with an errno in the filter and no line (race-free too, but a refusal the ledger never sees breaks the reason
channel's guarantee, and an errno arm would enforce under observe); performing an uncork (`UDP_CORK` 0) on the duplicate
instead of refusing it (a run that can set no cork has only a socket it was handed corked to uncork, whose datagrams the
relays refuse anyway); refusing relays on a connected socket; and closing the descriptor-swap
race in the decision plane, whose `socket_sendmsg` sees the message's flags and the socket race-free, for every
`sendmsg` path including `splice_to_socket` and io_uring: a BPF change to load-test on every kernel row, for a race only
a run that attacks its own descriptor table can enter, whose bytes reach only destinations the run admitted, and tier 1
would keep the supervisor's checks; it stays future work.

(2) *A credit row is serialized by its owner, by the map's own key.* Before, the supervisor serialized one-shot
credits by a key it built itself (`grantOnce`), apart from the key the granter writes, and the two drifted twice: by the
abstract name, which `tego_unix_approvals` keeps in the value, then by the IPv6 zone, which
`tego_connect_approvals` drops (two approved datagrams to one link-local address on two scopes wrote one
row, and one was refused `ask-unavailable`). Now cgroup's `Handle` holds the exact key value it writes with
`UpdateNoExist`, from the grant to its revoke (`creditRows`, at most a second, never past the run's end), so every field
the kernel keys a row by is in the serializing key and nothing it drops is; the supervisor serializes nothing. A revoke
reports whether its credit was left untaken, which (1) reads. Rejected: keeping the supervisor's key and dropping the
zone from it (the next field a map adds or drops drifts again); a key the granter exports for the supervisor to hold
(two owners of one invariant); a counted credit or a nonce in the value (a BPF change, and a delete from user space
cannot compare a value).

*Amended 2026-10-25 ([ADR 0100](0100-second-binary-and-handoff.md) (7)):* "the administrative caller must
be outside the governed cgroup and its descendants" becomes: outside every run's and adoption's scope and every
look-alike of one, and in the broker's cgroup namespace. The broker reads its peer by `peer.Identify` (the
`SO_PEERCRED` pid and uid, that pid's cgroup and cgroup namespace, proved by the peer's pidfd), at the connect and
again once the packet is in, and judges it by `peer.Refuse` beside this run's own cgroup: a peer of another run, a watched agent, an adopted process, a run's container, a process that unshared a
cgroup namespace, and every peer while the broker is outside the initial cgroup namespace are unauthorized, and the
ask stays pending for the person. A record-only watched agent is not a cage: it can leave its scope before it
answers, by a cgroup of its own in the person's delegated subtree (`cgroup.procs`) or through `systemd --user`, and
then answers as same-user software outside any run (X4); `tego watch --boundary` closes both (compile R10,
`builtin.host_ipc`). The uid rule is unchanged (the run's owner or root). The broker's list and detail
show every client a target in its ledger form (`askclient.LedgerTarget`), so an `http_request`'s path and query never
leave the run; the ask and answer lines already recorded that form.
