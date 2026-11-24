# ADR 0128: A run reads the host's network through NETLINK_ROUTE and does not change it

Status: **accepted 2026-11-01**; built (the aim: allow read-only route queries, keep
every way of changing the network refused). Amends
[ADR 0018](0018-socket-family-allowlist.md) (1) and (5) (AF_NETLINK of any protocol), [ADR 0070](0070-host-sockets-refused-by-default.md)
Decision 3 and its Consequences (a `net:` section refuses route queries), SEMANTICS §5, enforce-landlock E30,
enforce-plane R14, supervisor R7b and runtime-launch R4.

## Context

Under a contract with a `net:` section, and `tego init`'s starter has one, Node's `os.networkInterfaces()` and Python's
`socket.if_nameindex()` failed `EACCES`, and glibc's `AI_ADDRCONFIG` could not see which address families the host has.
The ledger said `net`, rule `unmatched`, reason `net-not-allowed`, `dst family(16)`. Claude Code and Codex are Node
programs, so this hit the agents the product is for, on an ordinary call. ADR 0070 relayed the same query for a contract
with no `net:` section, and left the `net:` case refused.

Reading the kernel's netlink path for this showed that two things the docs claimed held less than they said:

- **Refused sends are not all sends.** Seccomp sees `connect`, an addressed `sendto`, and `sendmsg`. It does not see an
  unaddressed `send(2)`, and it cannot see `write(2)`, `writev(2)` or an io_uring send without notifying every write of
  every program. An unaddressed send on a netlink socket goes to the kernel (`nl_pid` 0 is the default peer). So
  ADR 0070's "another netlink protocol stays refused" was true of addressed sends only, and a `net:` section's refusal of
  `family(16)` never stopped musl, whose `getifaddrs` uses plain `send`.
- **The socket opener's capability does not decide.** `netlink_sendmsg` sets `NETLINK_SKB_DST` on any addressed send, and
  `__netlink_ns_capable` then asks only the sender. A supervisor that made every route socket itself with no capabilities
  would stop an unaddressed change and not an addressed one.

Who can hold `CAP_NET_ADMIN` in a run:

| Run | Holds it? | Why |
|---|---|---|
| Tier landlock | never | empty capability sets and `no_new_privs`, always (ADR 0033); `setuid: true` has no effect |
| Tiers cgroup, bpflsm | never | the drop, then `no_new_privs` after it (runtime-launch R4) |
| Tiers cgroup, bpflsm, `setuid: true` | **it could** | no `no_new_privs`, so a setuid-root exec is granted capabilities up to the bounding set |
| A new user or mount namespace | not over the host | `CLONE_NEWUSER` is notified and refused, `clone3` is `ENOSYS`, every `setns` is refused |

## Decision

1. **Reads work.** Under a `net:` section, as already in the unix-only state, an addressed `sendto` or `sendmsg` without
   ancillary data on a `NETLINK_ROUTE` socket to the kernel (`nl_pid` 0, `nl_groups` 0) is relayed on the supervisor's
   duplicate, from the bytes it copied, as the task (`relayRouteQuery`, `SendToRawAs`), and recorded `allow`, rule
   `route-query`, `dst family(16)`, proto `raw`. Domain and protocol are read on the duplicate, which no sibling's `dup2`
   changes.
2. **What is relayed is read first, and only a GET is.** `routeReadOnly` walks the copied datagram the way
   `netlink_rcv_skb` walks it, so a GET cannot carry a NEWROUTE behind it, and admits a message only if its type is in
   rtnetlink's range and of the GET kind: the two low bits past `RTM_BASE`, the same test `rtnetlink_rcv_msg` uses to ask
   `CAP_NET_ADMIN` of every other kind. So the line between reading and changing is the kernel's own, not a list of ours
   that a new message type could fall through. Anything else (a NEW, DEL or SET, a control message, a length that overruns
   the datagram, trailing bytes) is refused and never sent: `EACCES`, rule `route-change`, reason `net-not-allowed`. The
   relay sends the copy it read, so a sibling that rewrites the buffer changes nothing. This holds in the unix-only state
   too, where the relay ran as the task with no such read, and a task holding `CAP_NET_ADMIN` could have had a change
   relayed.
3. **Under a `net:` section `AF_NETLINK` is `NETLINK_ROUTE` alone** at `socket(2)`, decided on the scalar protocol
   argument in the filter's arm, and the same in the plane's `socket_create` (`tego_socket_allowed`, which sees io_uring's
   socket op), `socketpolicy.Allowed` and `compile --test`. Another protocol is refused `EPROTONOSUPPORT`, what a kernel
   without it answers and what libaudit reads as no audit, with a refused line naming the triple. This is what makes "other
   protocols stay refused" true: refused at creation, there is no socket for an unaddressed send to use. With no `net:`
   section nothing changes (SEMANTICS §1): addressed sends on them stay refused `host-sockets`, as ADR 0070 says.
4. **A `setuid: true` run under a `net:` section never holds `CAP_NET_ADMIN`.** The privileged order takes it out of the
   bounding set first (`sys.DropBoundingCapability`, `ChildSpec.DropNetAdmin`), so no exec gains it and the kernel refuses
   every change, on the paths the supervisor sees and on those it does not: `write(2)`, an unaddressed `send(2)`, an
   io_uring send, `ioctl(SIOCADDRT)` and `SIOCSIFFLAGS`, `iptables`' setsockopts, `NETLINK_NETFILTER`. Only that capability
   goes; the run keeps what `setuid: true` is for. A launcher whose bounding set never had it has nothing to do, and needs
   no `CAP_SETPCAP`. Every other row of the table above already holds no capability, so decision 2's refusal is the
   record of an attempt there, and the kernel is what stops it.
5. **A bind under a listener policy.** A `net.listen` key notifies every `bind(2)`, and a netlink address, which no
   listener rule can name, was refused `args-unreadable`, so glibc failed before it sent anything. A bind of a
   `NETLINK_ROUTE` socket with no multicast group is made on the duplicate from the copy and recorded `allow`, rule
   `route-query`. It is no listener. A bind with a group is left to the refusal: some groups are checked against the
   caller (`rtnetlink_bind`), and at a root tier the supervisor would pass where the task does not.

## What the agent learns

This is an exposure, and it is on by default, under every contract. Through a route socket a run reads, for the machine
it runs on:

- interface names, indexes, flags, MTUs and hardware (MAC) addresses, and each interface's traffic counters (`RTM_GETLINK`);
- every IPv4 and IPv6 address of the host, the LAN's and a VPN's included (`RTM_GETADDR`);
- The routing tables: the default gateway, VPN subnets, container bridges (`RTM_GETROUTE`), and routing rules;
- The neighbour table: the IP and MAC addresses of other machines on the LAN the host has talked to (`RTM_GETNEIGH`);
- queueing disciplines, network namespace ids, and, on a socket bound to a group, live notice of all of these changing.

That can identify the machine and its network, and it can leave through any destination the contract allows, as anything
the agent reads can (GAPS A1). It adds little to what a run could already read: `/proc/net/route`, `/proc/net/arp`,
`/proc/net/dev` and `/sys/class/net` hold most of it, and no contract refuses them unless a `deny_read` entry names them
(`TestIntegrationRouteQueries` reads two of them). A run does **not** learn, through this, what other programs have connected where: `NETLINK_SOCK_DIAG`
is refused at `socket(2)` under a `net:` section, which is new, though `/proc/net/tcp` still lists every TCP socket in the
network namespace. Wi-Fi names (`nl80211`, generic netlink) are refused the same way.

There is no contract key to turn the read off, because it would be a promise the filter cannot keep: see Rejected.

## Rejected

- **A list of allowed GET types** (`RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`, leaving out the neighbour table). The list
  would hold only on the addressed paths; an agent that wants the neighbour table sends the same bytes with `send(2)`,
  which reaches the kernel with no notification. It would refuse `ip neigh` for honest programs and stop no one else, and
  say more in the record than it enforces.
- **A contract key to refuse route reads.** For the same reason it could only be kept by refusing `socket(AF_NETLINK)`
  outright, which fails Go's `net.Interfaces`, Node and glibc as this ADR's starting point did. If a deployment needs that,
  `/proc/net` has to go too; that is a separate decision.
- **The supervisor makes every route socket itself, with no capabilities, and installs it with `ADDFD`.** This was the first
  design, resting on the opener check in `__netlink_ns_capable`. That check is skipped for an addressed send
  (`NETLINK_SKB_DST`, Context), so it would have needed the bounding-set drop anyway, which alone is enough.
- **A BPF LSM program on `netlink_send`**, reading the skb. It would be exact at tier 3 and absent at tiers 1 and 2, where
  the same capability answer already holds.
- **Refusing `setuid: true` under a `net:` section.** `net.assurance: kernel`, `gate`, `ask` and held reads refuse it, for
  reasons about the whole boundary. Here one capability is what matters, and an agent that runs `sudo` for other
  reasons keeps working.
- **Admitting `connect(2)` to the kernel on a route socket.** It changes nothing about what a socket can reach, but
  no caller this fixes makes one (glibc, Go, libuv, iproute2, Python and musl do not), so it stays refused until one needs it.

## Consequences and residuals

- The interface lists of Node, Python, Go, psutil and glibc's `AI_ADDRCONFIG` work under a `net:` section. Each addressed
  query is one more `allow` line and one relay (OPERATIONS: about 8 µs per relayed datagram); a `net.listen` contract adds a
  bind line.
- **An unaddressed `send(2)` or `write(2)` on a route socket is neither decided nor recorded.** Its reach is the same as a
  relayed query's: a read works, and a change gets the kernel's `EPERM` in the ack, with no ledger line. So the ledger shows
  addressed attempts at a change, not every attempt; musl's dumps leave no line at all.
- **A socket the run did not make** (inherited, or received over a unix socket from something outside) is not bound by
  decision 3: its unaddressed sends reach the kernel as that protocol. Decision 4 still applies to its sender.
- **`net.assurance: kernel`** answered `recvmsg` `ENOSYS` (its connected-socket import rule), and glibc reads a netlink
  reply with `recvmsg`, so its interface lists failed in that mode: `if_nameindex` and `getifaddrs` failed `ENOSYS`, and
  Node's `os.networkInterfaces()` threw. This ADR did not change that (the filter cannot read a `msghdr`, so it cannot
  tell a route socket's reply from a unix socket's `SCM_RIGHTS`, and a supervisor's `CONTINUE` leaves the descriptor
  number a sibling can `dup2` over); the amendment of 2026-11-20 below does, where the decision plane runs the run.
  What reads with `recvfrom` always worked: `recv(2)`, and Go's `net.Interfaces`.
- **`io_uring: true`** sends are not notified, so they are in the unaddressed row above. At a tier where it is admitted
  the plane's `socket_create` holds decision 3.
- **A daemon can change the network for an agent** (NetworkManager over the system bus, `tailscaled`, Docker). That is
  a unix socket the contract must name; a `net:` section with no such `unix:` entry refuses it, as it always did.
- **With no `net:` section and `setuid: true`,** the agent keeps `CAP_NET_ADMIN`. That contract restricts no IP destination
  (SEMANTICS §1). Only the relay's read (decision 2) applies; `write(2)` changes the network there
  (`TestRootRouteChangesRefused`'s control).
- `sudo ip route add` and the like now fail under `setuid: true` with a `net:` section, by design. Compile's `setuid`
  warning says so. An agent that must change the network needs a contract with no `net:` section.
- On a route socket nothing bound, the relayed send autobinds with the supervisor's pid as its port id, as ADR 0070 states.
  Under a listener policy so does a relayed bind with `nl_pid` 0. glibc, Go and iproute2 read the port id back with
  `getsockname`; a program comparing `nlmsg_pid` with `getpid()` would notice.
- `sendmmsg` on a route socket stays refused under a `net:` section; no caller uses it.

## Amendment, 2026-11-20: the descriptor-import guard moves to the plane

Under `net.assurance: kernel`, where the run's decision plane attached `socket_recvmsg` (lsm or fmod_ret mode),
the strict filter no longer answers `recvmsg` ENOSYS. The plane refuses, with `EACCES`, and records (rule
`socket-import`) every receive on an `AF_UNIX` socket whose kernel-copied `msghdr` carries a control buffer
(`msg_controllen != 0`), before the protocol's receive can install a descriptor. A control receive on any other family
(`IP_PKTINFO`, a timestamp, a TOS or GRO size, `IP_RECVERR`) can import nothing and passes with no ledger line. A receive with no control buffer proceeds as `recvfrom` and `read`
already do, and the kernel drops any passed files (`MSG_CTRUNC`). `recvmmsg` and `pidfd_getfd` stay ENOSYS in the
filter. `socket_imports_denied` is satisfied by either mechanism, and a run with neither is refused before its agent
starts. glibc's `if_nameindex` and `getifaddrs` and Node's `os.networkInterfaces()` then work under kernel assurance
at every plane tier. A run with no plane keeps the filter's refusal and its interface-list residual.

Basis: the hook runs in `sock_recvmsg` before the protocol's receive, on the kernel's own copy of the `msghdr`
(`copy_msghdr_from_user` ran first), so no sibling thread can change `msg_controllen` between the test and the
receive. `SCM_RIGHTS` and `SCM_PIDFD` exist only on `AF_UNIX` and only through a control buffer: `scm_recv` installs
neither without one. `MSG_PEEK` with a control buffer is refused like any other, since a peek duplicates the passed
files into the receiver. Nothing new is reachable: the only receives newly admitted are those `recvfrom(2)` and
`read(2)` already make, on a socket the run holds, and the assurance never covered ingress. The errno for a refused
control-bearing `recvmsg` changes from ENOSYS to EACCES (ADR 0024 (7) lets the plane answer only 0 and EACCES), and the
refusal is now a ledger line where the filter's ENOSYS left none. `compat` `recvmsg` meets the filter's arch guard, and
`io_uring` is refused under strict assurance.

Where the guarantee sits: the plane, in the kernel, for a run whose slot header carries `TEGO_SLOT_IMPORTS_DENIED`
(its `net.assurance` is kernel and the hook is attached). The filter leaves `recvmsg` out of its client list only for
such a run (`landlock.Handle.PlaneImportsFilter`), from the first filter the child takes, not only after the runtime
uses the plane's fs answers. `cgroup.Handle.NetworkGuarantees` reports `SocketImportsDenied` for it only with the hook
attached and the slot flagged, so a drift between the two refuses the run before it starts.

What the guarantee covers: `SCM_RIGHTS` and `SCM_PIDFD` receives, and nothing else a socket can hand over.
`getsockopt(SO_PEERPIDFD)` (Linux 6.5 and later) gives the caller a pidfd for its socket's peer with no control buffer
and never went through `recvmsg`, so neither the old filter nor this hook covers it. It gives no more than
`pidfd_open` of the pid `SO_PEERCRED` reports, except across pid namespaces, and `pidfd_getfd` stays ENOSYS, so it
opens no descriptor of another process. It is out of scope here and stays open; closing it would take a `getsockopt` hook decided per run.

Where it depends: the old guard was the filter, which stays on each task whatever it does. This one is the run-set row
and the cgroup membership: it holds while the task is in a run's cgroup and the run's row, with the slot header, exists
(`bpf_get_current_cgroup_id` keys the hook). That stays sound for the reasons the rest of the plane rests on: the agent
cannot move itself out of the run's cgroup, the row and header are pinned and outlive a launcher that dies, and the
reaper removes them (purge of the dead slot) only after the run's cgroup is gone, that is after `cgroup.kill` and with
no task left in it; a row that cannot be removed keeps deciding for its tasks and keeps its slot allocated. A task whose
cgroup has no row meets the hook with no run, which is a pass, but such a task is not any run's agent. The filter and the
slot flag are chosen together at one place per side (`landlock.Handle.recvmsgInPlane`, cgroup's `fillPlane`), and
`NetworkGuarantees` reports `SocketImportsDenied` only when they and the attached hook agree.

Residuals:
- A run with no plane (tier cgroup on the fanotify fallback) keeps the filter's `ENOSYS` and the interface-list failure
  above; having the supervisor complete `recvmsg` on a route socket remains the follow-up only if such a host needs it.
- A run that holds its opens no longer keeps the filter's `ENOSYS` (amendment 2026-11-21, below).

### Amendment 2026-11-21: the open deputy is exempt by its identity

A run that holds its opens (`fs.reads: held`, or `gate.completion: held` with an fs gate) starts the open deputy, which
runs in the run's cgroup and takes each request socket and dirfd with `recvmsg` and a control buffer. Until now such a
run kept the filter's `ENOSYS` and its slot was not flagged, so its interface lists failed at every tier (found in
review, 2026-11-20). Now its slot is flagged like any other kernel-assurance run, its filter leaves `recvmsg` to the
plane, and `socket_recvmsg` passes the deputy alone: the launcher writes the deputy's thread-group id, its start time
(clock ticks since boot, as `/proc/<pid>/stat` field 22 gives it) and the launcher's pid namespace into the run's slot
header after the deputy's hello and before the run is armed, and the hook passes a control-bearing receive only when
the receiving task's thread-group id in that pid namespace (`bpf_get_ns_current_pid_tgid`) and its thread-group
leader's `start_boottime`, in the same ticks, are that pair. Every other task of the run is decided as before.

Why it cannot be forged from inside the run:
- *Another process*, a child the agent forks or a process that execs the deputy's image (`tego __open-deputy`), has
  its own thread-group id. A thread-group id is the identity, not the image.
- *A reused pid.* The launcher keeps the deputy's zombie unreaped for the whole run (`launch.Child.KeepUnreaped`), so no
  process of the run can be given its pid; a pid reused after the run, or in another pid namespace, carries another
  start time.
- *The deputy itself.* It is non-dumpable, so the agent can neither trace it nor reach its memory or descriptors
  through `/proc`; its seccomp allowlist kills it on `execve`, `execveat` and any `clone` without `CLONE_THREAD`, and
  answers `clone3` `ENOSYS` (`deputy.Filter`), so its identity never runs another image and never passes to a child.
  Its threads share its thread-group id and run its own code.
- *The write.* The pair is written before Arm inserts the run-set row, so no hook decides for the run while it is
  written; a pair that cannot be written (the deputy's start time unreadable) refuses the run before it starts, since
  the filter has already left `recvmsg` to the plane.

Residual: a launcher in a time namespace with a boot-time offset reads the deputy's start time shifted from the kernel's,
so it cannot name the deputy; such a run that holds its opens under kernel assurance is refused before it starts
(`cgroup.ErrDeputyNotExempt`), as any failure to write the pair is.

## Implementation notes

- 2026-11-01: `socketAllowTest`'s netlink block, `socketpolicy.Allowed`, `internal/bpf.SocketAllowed`, `tego_socket_allowed`
  and `TEGO_NETLINK_ROUTE`; `refuseSocket`'s errno; `routeSocket`, `routeQuery`, `routeReadOnly`, `relayRouteQuery`,
  `bindRoute`, `decidesNetlink`, and `resolveTarget`'s exception to `refusesUndecidable`; `sys.DropBoundingCapability`,
  `sys.InBoundingSet`, `launch.ChildSpec.DropNetAdmin`, `dropsNetAdmin`. Rules `route-query` and `route-change` add no
  field, so no record minor.
- The objects are the pinned toolchain's. `make gen`'s bytes depend on the checkout's path (`scripts/check-bpf-objects.sh`'s
  header says why), and that script, which makes them at its fixed path, finds all 49 generated files identical to the
  committed ones. Only `cgroupnet`, `planepr`, `planerd` and their adoption hashes changed; `TEGO_NETLINK_ROUTE` is in
  `socket_allow.h` and not `common.h` because a line added to `common.h` moves every object's line info.
- Tests: `TestRouteReadOnly`, `FuzzRouteReadOnly`, `TestRouteQueriesUnderANetSection`, `TestRouteConnectStaysRefused`,
  `TestRouteChangeInTheUnixOnlyState`, `TestBindOfARouteSocketUnderAListenerPolicy`; `TestFilterSocketAllowlist` and its
  parity tests, `TestAllowed`, `TestEvaluateSocket`, `TestSocketAllowedIsTheADR0018Table`, `planeStepBCells`;
  `TestDropBoundingCapability`, `TestDropsNetAdmin`, `TestPrivilegedOrderingSwap`; on the real kernel,
  `TestIntegrationRouteQueries` (one python3 probe, exact line counts), `TestIntegrationNodeInterfaces` and
  `TestRootRouteChangesRefused`, whose control is the same setuid-root probe with no `net:` section. Each fails with the
  old behaviour put back: the relay in the unix-only state alone gives `if_nameindex` `EACCES`, the item as found, and with
  decision 4 taken out the setuid-root probe under a `net:` section puts `10.77.0.1/32` on `lo` by `send(2)`, which is what
  a `net:` section allowed before this ADR. The root test ran in a KVM guest on 6.17 at tiers cgroup and bpflsm, on the
  `bpf` boot. The fmod_ret and fanotify planes ran only the socket cells (`planeStepBCells`), not this test.
- 2026-11-01 (later): Go's own `net.Interfaces` and `net.InterfaceAddrs`, named above and until now run only as python3's
  copy of their bytes, run under `net: {}`, a listener policy and no `net:` section at tier landlock
  (`TestIntegrationGoInterfaces`, workload `test/workloads/ifaces`). `TestStrictFilterInterfaceLists` holds the
  `net.assurance: kernel` residual on the real kernel, under the real filter, with no root: a listener continues the
  filter's other arms, as the supervisor would. It is the filter alone: no root-tier run of that assurance was made. Every
  contract's Always on rules now say a run reads this (`built-in.route-read`, rule `route-query`).
