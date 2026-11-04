# ADR 0018: under a net: section, socket(2) and socketpair(2) are admitted by an allowlist of what the network rules govern

Amended by [ADR 0128](0128-read-only-route-queries.md): (1) and (5)'s `AF_NETLINK` is `NETLINK_ROUTE` alone.

Status: accepted; PR 1 implemented 2026-09-24 (filter socketAllowTest, supervisor handleSocket, the ENOSYS default, TestEveryNotifiedSyscallHasAHandler, the ICMP compile warning; tier-1 kernel test TestSocketFamiliesOutsideTheNetRulesAreRefused). Two conditions of PR 1 as built: the MPTCP errno arm stays first and silent under a net: section too, since runtimes probe MPTCP and fall back to TCP, which is no policy event; and every refused socket is its own refused line, as every other refusal is, rather than one per binary and triple — the notification queue's flood handling is separate work. PR 2 implemented 2026-10-16 (its program, record and line built 2026-10-05; attached and pinned with the run's links wherever they attach, a required D7 row, the socket-family guarantee net.socket_families, which net.assurance: kernel requires, a test build's io_uring seam, and the perf budget socket.excess.cgroup_ns, 66 ns against a 300 ns target in a quiet guest, 164 to 302 ns in four runs on a loaded host on 2026-10-17, one of them a TARGET-MISS; TestSockCreateIsAttachedAndRefusesOutsideTheAllowlist, TestIOUringSocketsMeetTheKernelBackstops; dated notes below). Conditions of PR 2 as built: it attaches wherever the network programs attach, not only at the fanotify fallback; it refuses with the plain EPERM; it writes its own refused line with mechanism cgroup; io_uring stays ENOSYS at the fallback in a product build; the owner storage carries the ping flag and the generation. (7) added and implemented 2026-10-17 with PR 2 (the smc module's TCP ULP turned an admitted TCP socket into AF_SMC at every tier): under a net: section setsockopt(SOL_TCP, TCP_ULP) is refused whatever the name, by the filter's arm and the supervisor (ENOENT and a line) on setsockopt(2) and by cgroup/setsockopt (EPERM and its own line, mechanism cgroup) on any other path, io_uring's SOCKET_URING_OP_SETSOCKOPT included; cgroup/setsockopt is attached and pinned with cgroup/sock_create, a required D7 row, and the socket-family guarantee needs it; its cost on an option it passes is the perf budget setsockopt.excess.cgroup_ns, 155 to 259 ns against a 300 ns target (TestFilterNotifiesTCPULPUnderANetSection, TestSetsockoptRefusesTCPULPThroughIOURing; dated note below). PR 3 implemented 2026-09-29 inside ADR 0024 step B (TIER3-PLAN T13, docs/p0/enforce-plane.md §2.12): the plane's socket_create applies the allowlist under a net: section, io_uring's IORING_OP_SOCKET included; io_uring: true is admitted where a plane mode decides the run, whose unix names cgroup/connect_unix decides on 6.7+ and the plane's step D hooks (T15) below; elsewhere io_uring stays ENOSYS and enforce.Select warns. Proposed 2026-09-23. Amends enforce-cgroup-observe R4, enforce-landlock E30, SEMANTICS §5, supervisor (the dispatch default) and REASON-CHANNEL item 1.

Decision: (1) When the contract has a net: section, the seccomp filter (tier 1's, inherited at tiers 2 and 3) decides socket(2) and socketpair(2) on their scalar arguments. socket admits AF_UNIX (any type); AF_NETLINK (any protocol); and AF_INET/AF_INET6 only as (type & SOCK_TYPE_MASK) SOCK_STREAM with protocol 0 or IPPROTO_TCP, SOCK_DGRAM with protocol 0 or IPPROTO_UDP, or SOCK_DGRAM with IPPROTO_ICMP/IPPROTO_ICMPV6 when the contract has a port-0 (ICMP) entry. socketpair admits AF_UNIX only. Admitted triples get SECCOMP_RET_ALLOW. (2) Every other triple gets SECCOMP_RET_USER_NOTIF. The supervisor's socket handler answers it with EAFNOSUPPORT for a family and EPROTONOSUPPORT for an inet type or protocol (what a kernel without them answers, so runtimes fall back), and records refused, reason net-not-allowed, rule unmatched, with family, type and protocol in the payload, once per binary and triple with a count. The handler has no CONTINUE path. (3) The supervisor's answer to a notification it has no dispatch entry for changes from CONTINUE to ENOSYS, and a table test fails when any USER_NOTIF arm of the filter, on either arch, lacks a dispatch entry. With the listener closed the kernel already answers ENOSYS. So a refused triple reaches socket creation on no path. (4) With no net: section nothing changes (SEMANTICS §1); the MPTCP arm stays for that case and is subsumed otherwise. (5) At tiers 2 and 3 with a plane mode, ADR 0024 step B's socket_create body applies the same allowlist in the kernel to every family (kern != 0 returns 0), which covers io_uring's IORING_OP_SOCKET. In the fanotify fallback a cgroup/sock_create program joins the run's cgroup links (pinned with them, ADR 0020) and refuses inet sockets outside the set; it cannot see other families. io_uring: true is admitted only where the plane's socket_create is loaded and probed; elsewhere compile and run refuse it with a reason naming the residual. (6) compile warns when net: holds an ICMP entry, because ping sockets are decided by the supervisor only, best effort.

Why: [documented, R4 and E30 from kernel source] connect4/6 run only under sk_prot->pre_connect (tcp and udp protos, d74bad4e74ee), and Landlock's net hooks act only on sk_is_tcp/sk_is_udp, so SCTP and UDP-Lite are refused nowhere at tier 2 and their bind is unseen at tier 1.
[documented, net/socket.c __sys_socketpair and net/tipc/socket.c tipc_socketpair, checked today] socketpair has no filter arm and TIPC implements it.
[documented, internal/runtime/supervisor/notif.go handle()] An undispatched notification is answered CONTINUE, so a refusal by notification alone fails open on a missing or misnumbered entry.
[documented, net/ipv4/af_inet.c v6.1 and net/socket.c, checked today] BPF_CGROUP_RUN_PROG_INET_SOCK runs only in inet_create, while __sock_create calls security_socket_create for every family, including io_uring's socket op.
[inference] SCTP also associates through setsockopt(SCTP_SOCKOPT_CONNECTX) and one-to-many sendmsg; families outside AF_INET/AF_INET6 (AF_VSOCK, AF_TIPC, AF_RDS, AF_SMC, IPPROTO_SMC) are outside every net rule; an allowlist stays closed against the next such protocol, a blocklist does not.

Security argument: Admitted triples are decided in registers, so there is no TOCTOU. A refused triple reaches the supervisor, which only refuses; a missing dispatch entry now refuses (ENOSYS) instead of continuing; a dead supervisor refuses (ENOSYS). The arch and x32 guards keep compat socketcall out. At tiers 2 and 3 the kernel program covers creation paths seccomp cannot see, and io_uring stays refused wherever no such program runs. A runtime that needs another family gets a refusal line naming it, never a silent pass.

Options considered: Chosen: an allowlist on socket and socketpair, refused through a notification that can only refuse, with a fail-closed dispatch default; plane socket_create; cgroup/sock_create for the fallback.
Rejected:
- R4's own proposal (sock_create refusing non-TCP/UDP inet protocols plus a protocol arm): leaves every non-inet family open.
- SECCOMP_RET_ERRNO with no notification: fail-closed, but a policy refusal with no ledger line is a silence (ADR 0015); the chosen form is as fail-closed once the default is ENOSYS.
- Leaving it a stated gap: an egress path around net.allow at every tier.
- Refusing per protocol at connect or sendmsg: each protocol has its own association paths.

Consequence: R4's SCTP and UDP-Lite gap and E30's residue close at every tier; non-inet families close at tier 1 and, with a plane, for io_uring too. A contract that needs another family gets a refusal naming it; admitting one needs a net.proto entry form with a decision path per protocol (condition). The undispatched default hardens every other notify arm as well.

Implementation plan:

PR 1 (tier 1 and the default, after ADR 0017 v1): enforce/landlock filter.go socketAllowArm per arch, built from the compiled net section (replaces mptcpSocketTest under a net: section); supervisor handleSocket (answer and record, no CONTINUE) and the ENOSYS default in Loop.handle; a dispatch-completeness test walking the filter's arm table per arch against the dispatch map; the ICMP compile warning. Tests: filter unit tests over the arm table; tier-1 kernel tests on this host: SCTP, UDP-Lite, AF_VSOCK, AF_TIPC, AF_PACKET, SOCK_RAW, IPPROTO_SMC and socketpair(AF_TIPC) refused with the named errno and one line each; socketpair(AF_UNIX), AF_NETLINK, TCP and UDP work; no net: section unchanged. Smoke under a net: section: Go net/http, CPython httpx and getaddrinfo(AF_UNSPEC), Node fetch, curl, git clone over https, ping with and without an ICMP entry. ADR 0017's socket-family cells.
PR 2 (fallback backstop): bpf/cgroup_net.bpf.c SEC cgroup/sock_create reading ctx->family, type and protocol; attached in enforce/cgroup Attach beside connect4/6 and added to E36's doctor attach probe. Tests as root in GUEST and on MATRIX: the same cells at tier cgroup, plus an inet SCTP socket through io_uring refused by the program (a test build that admits io_uring without the plane).
PR 3 lands inside ADR 0024 step B: the plane's socket_create and io_uring: true admission.
Docs: ADR 0018; enforce-cgroup-observe R4; enforce-landlock E30 and the filter table; SEMANTICS §5; supervisor (dispatch default, socket handler); REASON-CHANNEL item 1 (the two errnos); agent-contract (io_uring: true's condition).

*Amended 2026-10-05 (ADR 0018 PR 2):* `cgroup/sock_create` is built in
`bpf/cgroup_net.bpf.c` and loaded with the `cgroup_net` object; it is not attached yet. Attaching and pinning it with
the run's links, the doctor D7 row, the socket-family guarantee and its perf budget are PR 2's second part. Decided
for PR 2, and built here:
- The allowlist is one C function, `tego_socket_allowed` in `bpf/include/socket_allow.h`, which the plane's
  `socket_create` (PR 3) now includes too. `internal/bpf.SocketAllowed` is its Go spelling, held to (1)'s table and
  to the filter's arm (`TestFilterSocketArmIsTheKernelAllowlist`). The filter differs in one cell: its MPTCP arm
  answers protocol 262 with `EPROTONOSUPPORT` in every family, AF_UNIX and AF_NETLINK included, where the kernel
  answers the same itself. A root test checks the C function in the kernel over the same table
  (`TestSockCreateRefusesInetSocketsOutsideTheAllowlist`).
- The refusal is the kernel's plain `EPERM` (`return 0`). There is no `bpf_set_retval`, which would need a second
  object build and a load-time probe. The supervisor answers `EAFNOSUPPORT`/`EPROTONOSUPPORT` and the plane `EACCES`;
  the ledger reason is `net-not-allowed` in all three.
- The program writes its own record, `TEGO_EV_SOCK_CREATE` (kind 28), on the run's ring, under `record: off` too. No
  recorder sees a socket's creation, so without it a refusal would have no line (ADR 0015). This amends
  enforce-cgroup-observe R5, which says the network programs never push an event, for this one program. The
  recorder turns that record into the existing `refused` line (`op: socket`, the triple as the supervisor spells
  it, `net-not-allowed`, rule `unmatched`). The payload carries `mechanism: cgroup` and no `decision_plane`,
  additive within v1, so no new kind or reason code is needed (`observe.handleSockCreate`). A record with another
  reason, or of a triple the allowlist admits, still writes its line and is a malformed-record gap.
- `struct tego_net_owner` gains `flags` (`TEGO_OWNER_NET_ICMP`, from `NetSocketPolicy`) and `gen`, so the program
  gets its ping rule and its record's generation from the attachment and not from a run-set lookup. A lookup keyed by
  the caller is what R1 forbids, and the run-set row keyed by the run's cgroup exists only from Arm on. The value
  grows from 24 to 32 bytes.
- The protocol is compared whole. MPTCP (262) is refused and recorded on this path. The filter's silent MPTCP arm
  stays for `socket(2)`, where runtimes probe it.
- An attachment `Attach` has not configured refuses everything, unrecorded, as the other network programs do (R1).
  The first plan admitted TCP and UDP there, which would have made this the one program that allows on an
  unconfigured attachment.

*Amended 2026-10-16 (ADR 0018 PR 2):* `cgroup/sock_create` is attached, and PR 2
is complete. Decided and built here:
- **Where it attaches (amends (5)'s "in the fanotify fallback").** `Attach` attaches it to the run's cgroup
  right after the CGROUP_SOCK_ADDR batch (`enforce/cgroup` `attachSocketPrograms`, with (7)'s `cgroup/setsockopt`
  since 2026-10-17), wherever that batch attaches: every
  tier-2 mode and tier 3, the fanotify fallback and a plane mode alike, and never for a contract with no `net:` section
  (R1). Its link is pinned with the run's others (ADR 0020 (1)), so a launcher killed outright leaves it deciding. With a
  plane mode the plane's `socket_create` runs first, in `__sock_create` before `inet_create`, so this program only ANDs
  the same inet verdict; one attach path and one pin set, and it still decides should a plane slot not. The cost is one
  program run per inet socket.
- **The owner it reads.** `Attach` writes the owner storage's `flags` (`TEGO_OWNER_NET_ICMP`, from
  `RuleTable.NetSocketPolicy`, the predicate the filter's arm and the plane's slot header read) and `gen` (the run's
  generation). The storage is keyed by the cgroup id alone, which the kernel shares between attach types, so the program,
  attached after the batch, reads the value already configured; a zeroed one would refuse every socket, never admit one.
- **Required.** The attach type is 4.10 and its `bpf_link` attach 5.7, below the floor, so a failure fails
  `Attach`: `EPERM` is `ErrCgroupAttachConflict`. Doctor's D7 has the row `cgroup/sock_create`, required for tier
  `cgroup`, and every cgroup row whose attach the kernel refuses with `EPERM` names the conflict in the words `Attach`
  uses (`cgroup.AttachConflictHint`, one helper).
- **The guarantee.** `backend.NetworkGuarantees.SocketFamilies`, the run_start key
  `net_guarantees.socket_families` and the capability row `net.socket_families` (appended, R23) say that every socket the
  run can make is one the allowlist admits, decided in the kernel on every path: tier 1's filter arm under a `net:`
  section with io_uring refused; at tier 2 that and this program attached, or a plane mode's `socket_create` (which also
  covers io_uring). `net.assurance: kernel` requires it ("socket family hooks"). A run with io_uring admitted and no
  plane `socket_create` does not have it: the filter never sees an `IORING_OP_SOCKET`, and this program sees inet only.
  As built here it missed a socket turned into another family after it was made (`TCP_ULP`); the 2026-10-17 note adds
  (7), and the guarantee now needs it.
- **io_uring at the fallback.** It stays ENOSYS in a product build, and the warning now names why: nothing on
  the fallback decides an `IORING_OP_SOCKET` of another family, a unix name below 6.7, or a file operation only the
  supervisor decides. A `-tags tegotesthooks` build admits it there under `TEGO_TEST_FALLBACK_IOURING=1` (never under
  AT_SECURE) only to prove the backstop, and says so in the run's warning.
- **Cost.** The perf suite's `socket` check (`test/perf`, `make vm-perf`) alternates socket(AF_INET, SOCK_STREAM,
  0)+close loops (200,000 a round, one pinned CPU, nine rounds) at landlock and on tier `cgroup`'s fanotify fallback,
  where nothing else a run attaches runs when a socket is made: `socket.excess.cgroup_ns` is 66 ns best-of-nine (3,140
  against 3,074 ns; medians 3,427 against 3,187 ns) in the 6.17 guest, under the 300 ns target and the 2,000 ns limit.
  The warm start is unchanged within the suite's noise: the root modes' best start over landlock's was 27 to 44 ms in
  two runs of the base build and 28 to 31 ms with this change (the suite's `start.warm.*` limits pass). A second run of
  the same tree on a loaded host (load average 26 on 16 CPUs, the landlock loop 3.9 times slower: 11,920 ns) printed
  `TARGET-MISS socket.excess.cgroup_ns 769 ns (limit 2000 target 300)`, within the limit; the 66 ns is the quiet
  guest's, and the target is judged there.
- **Tests.** Root, KVM guest 6.17 on the `lsm=...,bpf` and default boots: `TestSockCreateIsAttachedAndRefusesOutsideTheAllowlist`
  (owner flags and gen, the pin; with the sctp and smc modules loaded, SCTP, UDP-Lite, MPTCP 262 and SMC 256 `EPERM`,
  one record each on the run's ring),
  `TestSockCreateRunsAreANDedWhenNested`, `TestNetLinksOutliveTheLauncher` (refused after the launcher's SIGKILL),
  `TestAttachNamesALegacyExclusiveProgramAbove` and `TestD7NamesALegacyExclusiveAttachAbove` (a legacy exclusive
  `connect4` or `sock_create` program above), and `TestIOUringSocketsMeetTheKernelBackstops`: through `tego run`,
  io_uring sockets inline, from an io-wq worker (`IOSQE_ASYNC`) and from the SQPOLL thread are `EPERM` with one `refused`
  line each (`mechanism: cgroup`) on the fallback under the test seam, ENOSYS without it, and `EACCES` with the plane's
  line in each plane mode. Unit: `TestAttachOwnerCarriesTheICMPFlag`, `TestSocketFamiliesNeedTheFilterAndAKernelBackstop`,
  `TestSocketFamiliesFollowTheSocketArm`, `TestKernelAssuranceRequiresCompleteRunProof`, `TestSockCreateRowIsRequired`,
  `TestCgroupAttachRefusalNamesTheConflict`, `TestIOUringAtTheFallbackIsATestBuildsAlone`, `TestSocketInEveryMode`.
- **Kernel-matrix rows** (`TEGO_VM_ROW`, the `lsm=...,bpf` boot, 2026-10-16). `TestSockCreateIsAttachedAndRefusesOutsideTheAllowlist`,
  `TestSockCreateRunsAreANDedWhenNested`, `TestNetLinksOutliveTheLauncher`, `TestAttachNamesALegacyExclusiveProgramAbove`
  and `TestD7NamesALegacyExclusiveAttachAbove` pass on rhel-9 5.14, al2023 6.1, ubuntu-24.04 6.8, debian-13 6.12,
  al2023-6.12, fedora-7.0, fedora-7.2 and ubuntu-25.10 6.17, and `TestIOUringSocketsMeetTheKernelBackstops`, the fallback
  under the seam and both plane modes, on every one of them but rhel-9, which sets `kernel.io_uring_disabled` (its cells
  skip, root-skips). On rhel-9 the program's ring reservation and its map-in-map lookup work in a CGROUP_SOCK program: a
  UDP-Lite socket is `EPERM` with one record (that kernel makes no MPTCP socket). fedora-7.2 makes no UDP-Lite socket
  and refuses MPTCP. Failures on these rows that are not this program's: on rhel-9 the kernel refuses the perf links of
  the tracepoints `sys_exit_bind` and `sys_exit_listen` (`EPERM`), so doctor's `TestIntegrationAsRoot` and the
  network-control listener cells fail there, as they do for the tree this change was built on; on ubuntu-24.04 `TestIntegrationAsRoot` expects `fexit/io_bind` and
  `io_listen`, which are 6.11, on 6.8; on al2023 the harness's `tego doctor` step ran past its 300 s, as it did on
  2026-09-30.
- **Departures from the first plan.** Its C3 combined the guarantee as "inherited arm and (program or
  plane hook)"; here a run whose io_uring is admitted needs the plane's hook, since the filter then sees no socket the
  ring makes. Its C6 conformance cells belong to the net conformance cells  and are not built here; the root cells above stay
  the proof. The perf budget is measured by the perf suite's new `socket` check (landlock against tier `cgroup` on the
  fanotify fallback) rather than by a program detached in place.

*Amended 2026-10-17 (decision (7), added):* the socket-family bound
did not hold as the 2026-10-16 note built it, and now does. Decided and built here:
- **The hole.** `setsockopt(IPPROTO_TCP, TCP_ULP, "smc")` on an unconnected TCP socket the allowlist admitted turned it
  into an `AF_SMC` socket in place, with the `smc` module loaded (the Ubuntu 6.17 module carries the ULP,
  `tcp-ulp-smc`): it was reproduced in a KVM guest in all five cells (tier landlock, tier cgroup on the
  fanotify fallback, `lsm` and `fmod_ret`, tier bpflsm), `SO_DOMAIN` going from 2 to 43 with no ledger line, while
  `run_start` said `socket_families: true`. `smc_ulp_init` builds the new socket as a kernel socket: it never passes
  `socket(2)`, so the filter's arm does not see it; never `inet_create`, so `cgroup/sock_create` does not run; never
  `__sock_create`, so a plane's `socket_create` does not either. Destination rules still held (its connect runs on
  the TCP socket underneath, through `connect4`); the family bound is what failed.
- **(7) Under a `net:` section an upper-layer protocol is refused, whatever its name, at every tier.** A ULP is the one
  way a socket the allowlist admitted becomes one of another family, the ULPs a kernel offers are whatever modules are
  loaded (`tls`, `espintcp`, `smc`, and the next), and none is something the network rules govern, so (1)'s allowlist
  reasoning applies: refuse them all rather than list the dangerous ones. On `setsockopt(2)` the filter's socket arm
  notifies `SOL_TCP`/`TCP_ULP` on their scalar arguments (`enforce/landlock` `tcpULPTest`, both arches, the ints' low
  32 bits) and the supervisor refuses it (`handleSetsockopt`, no CONTINUE path) with `ENOENT`, what a kernel without
  that ULP answers, so a runtime that tries kTLS (OpenSSL with `SSL_OP_ENABLE_KTLS`) falls back to its own TLS, and
  writes a `refused` line, op `setsockopt`, target `TCP_ULP "<name>"` (`record.SocketOption`), the name read from the
  agent's memory for the line alone (min(optlen, 15) bytes, as the kernel reads; `TCP_ULP (name unread)` when it
  cannot be read), reason `net-not-allowed`, rule `unmatched`. At tiers 2 and 3 a new `cgroup/setsockopt` program
  (`bpf/cgroup_net.bpf.c` `tego_cg_setsockopt`) is attached and pinned beside `cgroup/sock_create` wherever the
  network batch attaches, required like it (5.3, `bpf_link` 5.7; a D7 row, `cgroup/setsockopt`, required for tier
  `cgroup`). The kernel runs it from `do_sock_setsockopt` for every option set on the run's sockets, whoever sets it, so
  it sees io_uring's `SOCKET_URING_OP_SETSOCKOPT` (6.7+), which no seccomp filter does; it refuses `TCP_ULP` with the
  plain `EPERM` and writes its own record (kind 29, `struct tego_ev_sockopt`, the name's first bytes from the kernel's
  own copy of the value, which is what the kernel then reads), which the recorder turns into the same `refused` line with
  `mechanism: cgroup`. Every other option passes untouched, the documented `PAGE_SIZE` rule aside: a value longer than
  the kernel shows a program is handed back with `optlen` 0, so the kernel uses the caller's value as with no program
  attached (5.11 to 6.4 would answer `EFAULT` otherwise). The kernel skips this hook for a compat syscall, which the
  filter's arch guard refuses anyway, and a compat task cannot set up a ring.
- **The guarantee.** `SocketFamilies` at tier 1 is the socket arm, which now carries the ULP arm, with io_uring
  refused. At tiers 2 and 3 the run's programs are `cgroup/sock_create` and `cgroup/setsockopt` both attached, and on
  top of them either the inherited filter's arm (no io_uring) or a plane mode's `socket_create` (io_uring admitted).
  A run with io_uring admitted and no plane still has none (a test build's seam on the fallback). The bound is on the
  sockets the run makes: one made outside it and passed in (`SCM_RIGHTS`, `pidfd_getfd`) is whatever family its maker
  chose, which `socket_imports_denied` bounds (the strict filter of `net.assurance: kernel`), not this row. Since the
  kernel runs the cgroup programs of the cgroup a socket was made in, a `TCP_ULP` set on such a socket meets the
  filter's arm on `setsockopt(2)` but no program through io_uring, which only a plane mode with `io_uring: true` admits
  and `net.assurance: kernel` refuses; the bound never covered such a socket.
- **Options rejected.** Admitting `tls`: at tier 1 the name is in the agent's memory, which a sibling thread can rewrite
  between the supervisor's read and the kernel's own copy, so an exact decision needs the supervisor to make the call
  itself on a duplicate of the socket; no runtime Tego governs uses kTLS by default, and one that asks falls back; a
  contract form for it is a condition, not built. A plane `socket_setsockopt` hook: the LSM hook has no option value,
  and a plane mode is not on every run, while the cgroup program is. Disclosure alone (`socket_families` false wherever
  io_uring is admitted): it would leave the conversion open in every plane run with `io_uring: true`. A silent errno
  arm, as the source-route arm is: an attempt at a family the contract cannot name is a policy event, and every
  refusal of one is a line (ADR 0015).
- **Errnos.** The supervisor answers `ENOENT`, `cgroup/setsockopt` `EPERM`; the ledger's reason is `net-not-allowed`
  for both (REASON-CHANNEL item 1).
- **Tests.** Unit: `TestFilterNotifiesTCPULPUnderANetSection`, `TestEveryNotifiedSyscallHasAHandler` (with a
  `TCP_ULP` argument shape), `TestTCPULPIsRefusedAndRecorded`, `TestSocketOption`, `TestSocketFamiliesFollowTheSocketArm`
  and `TestSocketFamiliesNeedTheFilterAndAKernelBackstop` (with the program), `TestSetsockoptRefusesEveryTCPULPOnTheAttachmentsRun`
  (source), `TestRecorderNamesSockoptRefusals`, `TestRecorderSockoptRecordOutOfShapeIsAGap`, `TestDecodeSockopt`,
  `TestSockCreateRowIsRequired`, `TestMachineMatrixSocketFamiliesNeedBothSocketPrograms`, `TestSetsockoptInEveryMode`.
  Integration at tier 1 on this host: `TestSocketFamiliesOutsideTheNetRulesAreRefused` (`ENOENT`, the line, the socket
  still `AF_INET`). Root, KVM: `TestSetsockoptRefusesEveryTCPULP`, `TestSetsockoptRefusesTCPULPThroughIOURing` (inline,
  async, SQPOLL), `TestSetsockoptCountsALostRecord`, and the run cells above extended: the pin and a `TCP_ULP` refusal
  with one record (`TestSockCreateIsAttachedAndRefusesOutsideTheAllowlist`), refused after the launcher's SIGKILL
  (`TestNetLinksOutliveTheLauncher`), a legacy exclusive `setsockopt` program above
  (`TestAttachNamesALegacyExclusiveProgramAbove`, `TestD7NamesALegacyExclusiveAttachAbove`), and through `tego run` in
  every mode (`TestIOUringSocketsMeetTheKernelBackstops`: `setsockopt(2)` the supervisor's `ENOENT` and line, io_uring's
  `EPERM` with one `mechanism: cgroup` line per submission mode), tier `bpflsm` included where LSM mode passes, each
  run's `run_start` held to its bound (`net_guarantees.socket_families` and the `net.socket_families` row true in every
  plane mode, at tier `bpflsm` and on the fallback with io_uring refused, false on the fallback under the test seam,
  where nothing decides an `IORING_OP_SOCKET` of another family). The supervisor's read of the name for its line is
  bracketed by `ID_VALID` like every read of the target (supervisor R2, I1; `TestTCPULPNameReadIsBracketed`): as first
  built it was a bare read, which a reused pid would have answered.
- **Cost.** The perf suite's `socket` check now loops `setsockopt(IPPROTO_TCP, TCP_NODELAY)` on one socket in the same
  runs as the socket loop (`openbench -setsockopt`): the filter admits it at both modes and only `cgroup/setsockopt`
  sees it on tier `cgroup`'s fanotify fallback, so the difference, `setsockopt.excess.cgroup_ns` (limit 2,000 ns,
  target 300 ns), is the program's cost on an option it passes, the kernel's copy of the value included. Four runs of
  the 6.17 guest (`lsm=...,bpf`) on 2026-10-17, on a host that other work kept at load average 4 to 20 on 16 CPUs (the
  landlock socket loop at 4,025 to 5,546 ns, against 3,074 ns in the quiet run above): 161, 155, 228 and 259 ns.
  `socket.excess.cgroup_ns` in the same runs: 164, 302, 235 and 174 ns; the 302 printed `TARGET-MISS
  socket.excess.cgroup_ns 302 ns (limit 2000 target 300)`. The warm start's new `attach` phase (the run's links and
  pins; enforce-plane §10.1) was 0.7 to 1.0 ms with the two programs and 0.6 to 0.8 ms in four runs of the base tree
  with the same phase mark added for the comparison, and every `start.warm.*` budget passed in all eight runs: the
  two links and pins cost 0.1 to 0.2 ms of a 70 to 90 ms start.
- **Kernel-matrix rows** (`TEGO_VM_ROW`, the `lsm=...,bpf` boot, 2026-10-17, this tree): `TestObjectsLoadOnThisKernel`
  loads `cgroup_net` with `cgroup/setsockopt` on rhel-9 5.14, al2023 6.1, ubuntu-24.04 6.8, debian-13 6.12,
  al2023-6.12, fedora-7.0, fedora-7.2 and ubuntu-25.10 (its `bpf_get_current_pid_tgid` and ring helpers verify in a
  `CGROUP_SOCKOPT` program on all of them), and `TestSetsockoptRefusesEveryTCPULP`, `TestSetsockoptCountsALostRecord`,
  the run cells above and `TestD7NamesALegacyExclusiveAttachAbove` pass on every row. `TestSetsockoptRefusesTCPULPThroughIOURing`
  passes on each row from 6.8 on and skips on rhel-9 (`kernel.io_uring_disabled`) and al2023 6.1 (no
  `SOCKET_URING_OP_SETSOCKOPT` before 6.7), as root-skips lists. Failures on those rows that are not this change's, as
  on the 2026-10-16 rows: rhel-9's doctor `TestIntegrationAsRoot` (the `sys_exit_bind` and `sys_exit_listen` perf
  links refused `EPERM`), ubuntu-24.04's (it expects the 6.11 `io_bind`/`io_listen` hooks on 6.8), and the unlisted
  skips of `TestObjectsLoadOnThisKernel/trace_proc/tego_uring_bind_result` and `tego_uring_listen_result` on al2023 and
  ubuntu-24.04, whose kernels predate those hooks.
- **How CI holds the root cells.** The plan (C6) put the new root tests in
  `test/vm/root-must-pass.txt`. The `internal/bpf` cells that need no io_uring are there
  (`TestSetsockoptRefusesEveryTCPULP`, `TestSetsockoptCountsALostRecord`, beside the socket program's two). The run cells
  in `enforce/cgroup` and doctor's D7 cell cannot be: they load the objects, so `test/vm/root-skips.txt` lets their
  plain (untagged) build skip them, and `scripts/check-skiplists.sh` refuses a test that is in both lists. They are
  held anyway: root-suites gates the tagged builds against root-skips without its `untagged:` entries
  (`root-skips.tagged.txt`), so a skip of one of them in the tegobpf build, which CI's `VM_BPF=yes` always runs,
  fails the job, and a renamed or removed one fails `check-skiplists.sh`, since its entry then names no test.


### C40 narrowing — 2026-11-03

ADR 0113's immutable socket identity refusal now takes precedence over this ADR's root-tier
`io_uring: true` admission. The compiler refuses that opt-in when an enforcing contract may select
cgroup or bpflsm: raw-name Unix trie hooks do not carry the relay's peer-inode alias checks. The
kernel socket-family programs remain available, but ring admission needs an identity-safe kernel
path before it can be exposed again. Root startup tests cover both an absent listener section and
an explicit listener allow. Landlock-only ring policy remains ENOSYS.
