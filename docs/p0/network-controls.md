# Network controls

Network destination admission, local listeners, ingress admission, packet
budgets and DNS query admission are separate controls. A declaration for one
does not grant authority for another. The run's `run_start.net_guarantees`
records the mechanisms actually prepared for that run; selecting a tier alone
does not prove that its optional hooks are available.

This document describes supported policy behavior. Acceptance on real kernels is recorded in `test/vm/README.md`.

```yaml
net:
  allow: ["tcp://198.51.100.10:443", "udp://198.51.100.20:9000"]
  listen: ["tcp://127.0.0.1:8080"]
  ingress:
    - from: "127.0.0.1/32"
      to: "tcp://127.0.0.1:8080"
  limits:
    connections: 32
    pending_connects: 8
    bytes: 16MiB
    datagrams_per_second: 20
  dns:
    mode: broker
    allow: ["api.example", "*.service.example"]
    types: [A, AAAA]
    max_parallel: 8
    cache: 128
    max_stale: 30s
```

## Destinations and listeners

Bare `host:port` destinations retain their existing TCP-and-UDP meaning.
`tcp://host:port` and `udp://host:port` select one transport. Literal addresses,
CIDRs and hostname resolution keep their existing refusal precedence and
declared exceptions. A listener requires an explicit `tcp://` or `udp://`
selector with a literal local address, or an ordinary `unix:` endpoint; DNS
names and CIDRs cannot identify local bind addresses.

An omitted `net.listen` adds no new listener restriction and preserves the
existing backend's rights: under a `net:` section those are unix listeners and
UDP binds, and no TCP listener (enforce-landlock R6). *Amended 2026-11-01:* that
holds for a `listen()` with no bind too, which Landlock's `BIND_TCP` never sees;
the supervisor refuses it and records the refusal. With no `net:` section nothing
is restricted. An explicit `listen: []` denies listener binds and
listens, unix ones included. A nonempty list grants only its declared endpoints. Address wildcards
cover narrower addresses in their own family; IPv6 wildcard declarations do not
silently grant IPv4 binds. IPv4-mapped address spellings normalize to IPv4.
Port `0` grants ephemeral allocation only, not every fixed port. Successful
allocation is attributed to that socket, so its subsequent `listen()` can use
the actual allocated port. The supervisor keeps these attributions per run for
the 65,536 most recent port-zero binds, by socket cookie: a socket left bound
and unlistened while that many later port-zero binds happen loses its
attribution, and its `listen()` on the allocated port is refused (amended
2026-10-05: the oldest attribution makes room; the newest was dropped, so
after 65,536 port-zero binds in one run every later port-zero `listen()` was
refused). Calling `listen()` without a preceding bind needs
an applicable port-zero declaration; a fixed-port grant cannot authorize that
autobind.

Pathname Unix listeners also require filesystem mutation authority on their
actual parent. Compilation resolves the parent and preserves the final name.
Abstract names use the bytes following the first `@` in `unix:@name`; another
`@` is part of the literal name. The available Landlock abstract-socket scope
remains an additional domain restriction. Listener declarations do not grant
filesystem write access or connect access to the resulting endpoint.

IP binds and listens are performed on the held original socket with frozen
arguments. Unix continuation on a backend without the copied-name decision
plane retains its explicitly weaker supervisor guarantee. Where the actual
plane and syscall-result producers are available, Unix bind/listen decisions
use the kernel's socket or created pathname and record the actual terminal
result. *Amended 2026-10-05:* that includes io_uring's `IORING_OP_BIND` and
`IORING_OP_LISTEN` (6.11+), which no bind or listen syscall exit sees; their
operations' own exits record them (enforce-plane §2.20). `net.assurance: kernel` requires the relevant attached mechanisms
before agent execution. *Amended 2026-10-16 (ADR 0018):* they include the socket-family bound,
`net_guarantees.socket_families`: the inherited filter's socket arm with io_uring refused and `cgroup/sock_create`
attached, or a plane mode's `socket_create`; a run without it is refused before the agent starts ("socket family
hooks"). *Amended 2026-10-17 (ADR 0018 (7)):* and `cgroup/setsockopt` attached in either case, which refuses an
upper-layer protocol (`TCP_ULP`, the way an admitted TCP socket became `AF_SMC`) on every path the filter does not
see. It holds wherever tier `cgroup` or `bpflsm` attaches its network programs. Landlock port rights alone do not prove address
confinement. Its ABI-dependent bind rights remain an additional restriction.

## Ingress and reply state

An omitted `net.ingress` adds no source-prefix restriction. An explicit
`ingress: []` admits no unsolicited ingress to declared listeners. Each ingress
entry references an exact declared IP listener and grants a literal source
address or canonical CIDR. Unix listeners have no IP ingress rules. Both lists
are bounded to 256 declarations. An ingress list requires an explicit listener
list.

Ingress controls require a `cgroup` or `bpflsm` run with working bind/listen,
post-bind, socket-lifecycle and packet attachments. A missing required
mechanism refuses startup, including when destination assurance keeps its
default `best-effort` setting. These are run-scoped cgroup attachments; they do
not alter the host firewall.

Packet admission supports complete, nonfragmented IPv4/IPv6 TCP and UDP.
Fragments, IPv6 extension chains or jumbograms, unsupported protocols and
malformed packet headers fail closed when these packet controls apply.
Admission records bounded reply state keyed by the run generation, exact
local/remote tuple and socket cookie. A new TCP SYN rechecks the listener and
source policy. Reply state is an inactivity cache, not evidence of a connection
being alive; its lifetime is 30 seconds for UDP and 30 minutes for TCP.

Ingress admission does not widen `net.allow`. TCP writes on an admitted
accepted socket can send replies without a new connect. An addressed UDP
`sendto`/`sendmsg` reply still needs ordinary egress destination admission.
The packet reply state then prevents an additional packet-policy refusal of
that permitted reply. Allowed endpoints, helpers and opaque connections remain
trust boundaries; packet controls do not inspect application messages.

## Network resource budgets and accounting

An omitted limit is unbounded; an explicit zero permits none of that resource.
`net.limits` requires working kernel network attachments in `cgroup` or
`bpflsm`, independently of destination assurance.

| Field | Charging and release |
| --- | --- |
| `bytes` | Admitted egress IP bytes, including IP/transport headers and TCP retransmissions. It counts local admission before a later queue or remote peer can drop the packet. |
| `datagrams_per_second` | Admitted egress UDP packets in a fixed monotonic one-second window. This is not a sliding-window or application-request rate. |
| `connections` | Conservative socket reservations shared by the run: pending/established TCP, UDP socket lifetimes and admitted inbound SYN reservations. TCP close or inet socket release frees an owned reservation once. |
| `pending_connects` | TCP reservations before establishment, including admitted inbound SYNs. Establishment transfers a reservation out of pending; close releases it. |

Uncompleted inbound SYN reservations persist until establishment or run
teardown. They bound incomplete connection pressure and may conservatively
exhaust a cap. Flow-cache expiry does not free these reservations or claim to
observe a real close. All per-run ceilings apply across descendants.
*Amended 2026-10-05:* an admitted inbound SYN's reservation ends at
establishment, 75 seconds after its admission, or run teardown, whichever is
first. The kernel reports no request socket it drops, so a peer that never
completed its handshakes held the run's cap, and rows of the build-wide pending
map, until teardown. The expiry claims no close: a handshake that completes
after it finds no reservation, and its final ACK is refused. A refused SYN or
socket reservation keeps no row. The reservation maps (16384 inbound SYNs,
65536 sockets) are shared by every run of one build and a run holds rows only
for the reservations it admitted; concurrent runs whose admitted reservations
together exceed a map contend for it, and an insert into a full map is refused
(fail closed) without a `denied_*` count. Per-run maps are not built.
*Amended 2026-10-05:* that expiry is a `bpf_timer` armed by the cgroup_skb
ingress program, and cgroup_skb programs have `bpf_timer_init`,
`bpf_timer_set_callback` and `bpf_timer_start` from Linux 5.15 (or a kernel
with them backported), above the 5.14 floor doctor D1 checks. On a kernel
without them the verifier refuses that program, so a run that declares
`net.ingress`, `net.limits.connections` or `net.limits.pending_connects`, each
of which requires it, fails closed at load before agent execution (R3, R4)
where it used to run; a run that declares none of them does not load it and is
unaffected. Doctor D7 reports this on its `optional network controls: N of M
hooks load and attach` clause, whose `cgroup_skb/ingress` row loads this
build's program.

Ingress bytes and datagrams are measured separately and are not charged to the
egress ceilings. These charges cover run-owned socket traffic: privileged
helper/proxy/broker traffic and pipe transports are explicit trust boundaries,
not a cap on every indirect byte. Default `best-effort` assurance does not
promise socket-import confinement; `kernel` assurance separately restricts
those import paths. `run_end.network` reports available counters explicitly;
unavailable values are absent, not measured zeros. Packet totals and refusal
counters are monotonic. `connections_active` is a reservation gauge that
includes pending TCP and UDP socket reservations; `connections_pending` is
the current pending gauge. Kernel snapshots hold the shared map lock so a
pending-to-accepted transfer cannot be reported halfway through.

## DNS expiry and one-shot approvals

`net.dns.max_stale` limits how long a hostname grant may retain a resolved
address after its TTL expires. That TTL is tego's fixed 60s re-resolution
interval, not the record's: the system resolver exposes no record TTLs, so a
grant expires 60s plus `max_stale` after its last successful lookup whatever
TTL the name's records carry (amended 2026-10-05: this said "its DNS TTL",
which read as the record TTL). `0s` allows no stale interval and omission
retains the existing unlimited-stale behavior. Values range from `0s` to `24h`.
Literal/CIDR grants and owned runtime endpoints do not acquire DNS expiry.
Overlapping grants retain normal refusal precedence and declaration attribution
at each deadline. Expiry removes only the expired grant: an independent live
grant can still permit the destination. Kernel monotonic decision timelines
apply deadlines without waiting for the DNS refresh ticker; a row requiring
more than 16 decision intervals is rejected before launch. A bounded grant is
re-resolved ahead of its deadline, once the run's 5s refresh tick plus the 3s
lookup timeout no longer fit before it (never sooner than 30s after its last
lookup), so a lookup that brings the same answer renews it without a refused
interval (amended 2026-10-05: renewal began only at the deadline, refusing an
unchanged destination for up to a tick plus a lookup once a minute at
`max_stale: 0s`).

An authenticated approval can supply one credit for an otherwise refused
ordinary TCP connect, or, since 2026-10-19, for an otherwise refused UDP
connect or addressed UDP datagram a person approved (supervisor R13d). The
credit is a row of `tego_connect_approvals` keyed by the run's slot and
generation, the socket cookie, and the copied destination's family, protocol,
address and port; it expires after one second and is revoked on every relay
outcome. A TCP credit is taken by that socket's `connect4/6` to that
destination alone; a UDP credit by the first of that socket's `connect4/6` or
`sendmsg4/6` to that destination. Normal policy allows do not spend it. The
grants of one row are serialized by the map's own key (cgroup `creditRows`),
and the revoke reports a credit left untaken, which the supervisor records
`observed`, not the person's allow (supervisor R13d). Credits do not authorize
a different socket, destination or transport (a TCP credit admits no UDP
operation and the reverse), Unix sends (whose one-shot grants are
`tego_unix_approvals`, supervisor R11c), or future packets that independent
packet controls refuse. *Amended 2026-10-20:* this
paragraph said credits are TCP-connect-only and never authorize UDP.

## Cooperating DNS broker

`net.dns.mode` defaults to `system`. `off` removes implicit agent resolver
transport grants (and `compile --test` answers a row to a machine resolver
accordingly, amended 2026-10-05: it answered `net.resolver` in
every mode); it does not inspect an explicitly allowed endpoint's
application protocol. `broker` supplies a private Unix `SOCK_SEQPACKET`
endpoint for cooperating clients, including `tego dns`. It does not change
glibc's resolver or make ordinary applications read a new resolver variable.
Host-side resolution used to compile destination grants still follows machine
resolver configuration.

The runtime sets `TEGO_DNS_BROKER_DIR` and `TEGO_DNS_BROKER_PID` after contract
environment processing, and strips inherited or forged values when disabled.
The directory identifies the short private socket directory, not the ledger
directory. The broker socket is an exact runtime network grant, without a
directory-read grant or implicit agent UDP access to the machine resolvers.
The CLI accepts `--run-dir` and `--server-pid` for an explicit authenticated
endpoint.

Admission requires the actual per-packet sender's live PID identity, expected
UID and membership in the governed run cgroup. A matching UID alone is
insufficient. A supervisor-relayed connection can name only the verified
launcher as connector; it still authenticates the actual governed packet
writer. Descriptor passing, ambiguous credentials and truncated packets are
refused. The socket is published before enforcement preparation and the
service becomes ready before the agent executes.

Broker name omission allows all valid names; `allow: []` denies all. Exact names
and `*.suffix` declarations match label boundaries; the wildcard does not
include the suffix itself. Omitted types default to `A` and `AAAA`; an explicit
empty type list permits none. Name and type matching is bounded. Queries have
one IN-class question, validated EDNS framing and a maximum 4096-byte packet.
`max_parallel` defaults to 8 and ranges from 1 to 16. `cache` defaults to 128
entries and ranges from 0 to 512; zero disables caching. Cached responses age
their TTLs and expire within the minimum record TTL or 300 seconds.

Configured numeric upstreams use connected UDP with fresh request IDs and
matching response questions, bounded deadlines and TCP fallback for truncated
responses. One deadline per request, counted from the broker accepting the
client's connection (2s), bounds reading the query, recording the decision and
the upstream exchange; a request that reaches it without an upstream answer gets
SERVFAIL, recorded as an `upstream unavailable` completion, and an answer
arriving after it is not delivered (amended 2026-10-05: the exchange had a
deadline of its own, so a silent upstream left the client with a closed
connection, and a late answer could be recorded as completed but never sent). The broker forwards DNSSEC data but does not validate DNSSEC or
prove the trustworthiness of an allowed name/upstream. Query names can carry
data to an allowed domain.

DNS ledger metadata records the known agent-to-broker Unix transport, name,
type, phase, cache flag and verdict, without response bodies. Successful query
decisions are recorded before upstream dispatch when telemetry is enabled;
refusals are mandatory even with `record: off`. Completion is recorded after
dispatch or a cache hit. A completion write failure withholds the response but
cannot retract a query already sent upstream.

Shutdown closes and joins the broker before closing the ledger, then removes
only the held owned socket and empty private directory. A detached reaper
inherits the exact cleanup descriptors and performs the same identity-checked
cleanup after launcher death and run-tree removal. Replacement objects are
preserved; cleanup never scans or sweeps arbitrary `/tmp` entries. That reaper
starts as soon as the socket is bound, before enforcement preparation, and is
handed the tier's kernel state afterwards (ADR 0020, amended 2026-10-05: it
started after preparation, so a launcher killed while preparation loaded BPF
left the directory and socket behind). A reaper that cannot start fails the
run before preparation.

See [policy semantics](../../spec/policy/SEMANTICS.md) for the destination,
filesystem and proxy decision floors.

## No `net:` section: the host's daemon sockets

A contract with no `net:` section admits every IP destination and reaches only
its own unix sockets ([ADR 0070](../adr/0070-host-sockets-refused-by-default.md),
SEMANTICS §1 and §5): a connect, or an addressed datagram, to a pathname or
abstract socket the run did not bind is refused, reason `net-not-allowed`, rule
`host-sockets`, and the line's `what` names what a well-known daemon socket
gives (`the Docker daemon, root-equivalent`). The runtime's own endpoints the run
admits today (the forwarder's listeners, the DNS broker's socket) stay reachable.
The opt-out is the top-level `host_sockets: true`, all or nothing; only the
contract file itself can set it (a profile cannot loosen it), and `run_start`
records it. The precise form is a `net:` section with one `unix:` entry for the
socket the agent needs, beside the hosts it reaches:

```yaml
net:
  allow:
    - "github.com:22"                         # git over ssh
    - "unix:/run/user/1000/ssh-agent.socket"  # the agent's $SSH_AUTH_SOCK
```

At tier landlock the supervisor performs every such connect, every Fast-Open
send, every send on a stream socket without a peer, and every addressed datagram
it can reproduce exactly, on its own duplicate of the socket from the copy it
decided, so neither a rewritten address nor a descriptor another thread swapped
in reaches a host socket (an addressed send on a connected socket, whose address
the kernel ignores, is neither decided nor recorded: a unix stream one gets the
kernel's `EISCONN` on the duplicate, an IP stream one goes to the peer on it); Landlock's `RESOLVE_UNIX` (ABI 9) and the
abstract-socket scope (ABI 6) refuse the same in the kernel behind it. A connect,
addressed datagram or stream send on a socket whose domain is neither IP nor unix
(`AF_NETLINK`, `AF_PACKET`) is refused, keyed on the socket's own domain, and
never relayed with the supervisor's credentials, save a route query: a read-only
send on a `NETLINK_ROUTE` socket to the kernel (`nl_pid` 0, no group), relayed as the
task and recorded allow, so `getifaddrs`, `if_nameindex` and
`getaddrinfo(AI_ADDRCONFIG)` keep enumerating interfaces (a `net:` section does the
same, and refuses other netlink protocols at `socket(2)`; ADR 0128). A send the supervisor cannot reproduce (ancillary data, `MSG_MORE`,
a `sendmmsg` batch, or an addressed send on a connected seqpacket socket) is
continued, best effort (`run_start.best_effort` `host_sockets/datagram`); the
agent chooses its calls' shape, so it can choose a continued one. At
tiers cgroup and bpflsm the same relay and Landlock carry it, with no kernel
program of the run deciding it: best effort (`host_sockets/root-tier`) until
the root tiers carry a kernel program for it. glibc's clients of nscd,
`nss-resolve` and `nss-systemd` fall back to files and DNS when their sockets
are refused, so name and user lookups keep working.

## 5. Business rules

**R1 — Independent authorities.** Destination, listener, ingress, packet-budget
and cooperating DNS declarations grant separate authority. Actual prepared
mechanisms determine the recorded guarantees; selecting a tier is insufficient.

**R2 — Listener admission.** Omitted listener policy preserves legacy rights,
which under a `net:` section hold no TCP listener, by bind or by autobind;
an explicit empty list denies binds and listens. A declaration grants its exact
transport/address/port, with the documented wildcard, mapped-address and
socket-bound ephemeral allocation semantics. Unix pathname creation also needs
filesystem mutation authority.

**R3 — Ingress admission.** Explicit ingress references declared IP listeners
and admits only matching source prefixes or established reply state. Required
kernel attachments must be available before agent execution. Packet parsing
fails closed for unsupported or malformed packets when these controls apply.

**R4 — Budget charging.** Requested ceilings apply across the run's descendants
with the charging and release semantics stated above. Admitted egress IP bytes
and datagrams are charged; ingress counters are separate. Conservative live
socket/SYN reservations remain reserved until the measured transition or run
teardown. Unavailable accounting is absent rather than a measured zero.
*Amended 2026-10-05:* an admitted inbound SYN's reservation also ends 75
seconds after admission, and that expiry needs `bpf_timer` in cgroup_skb
(5.15+), as stated above.

**R5 — Expiring grants.** A hostname grant's maximum stale deadline applies in
kernel decisions without waiting for refresh. Expiry removes that grant alone
and preserves independent active grants and refusal precedence. An over-capacity
decision timeline refuses preparation. Renewal starts a refresh tick plus a
lookup timeout before the deadline, never sooner than 30s after the last
lookup, so an unchanged answer does not lapse the grant (amended 2026-10-05).

**R6 — Connect approvals.** An approved ordinary TCP connect, and an approved
UDP connect or addressed UDP datagram (supervisor R13d), receives at most one
short-lived slot/generation/socket-cookie/exact-destination credit, keyed by
family, protocol, address and port, so a credit of one transport is never
taken by the other's operation. It cannot authorize another destination,
socket, transport or future packet-policy bypass. Grants of one key are
serialized (cgroup `creditRows`), and the credit is revoked on every relay
completion path; the revoke reports a credit left untaken. *Amended
2026-10-20:* R6 named the TCP connect alone.

**R7 — Cooperating DNS.** Broker queries require a live governed packet sender
and matching UID, bounded valid wire framing, and the declared name/type policy.
Allowed decisions precede upstream dispatch; completion failure withholds the
reply without pretending to retract upstream traffic. A broker is not a libc
resolver override, DNSSEC validator or allowed-domain data-channel preventer.

**R8 — Owned cleanup.** Ordinary shutdown and detached reaping remove only
identity-checked owned endpoint objects. Reaping waits for the run tree to be
empty. Foreign replacements are preserved, and cleanup never scans arbitrary
runtime directories.

**Changes.**
- 2026-10-25, the same section (ADR 0070 (3)
  amended): an addressed send on a connected socket is neither decided nor
  recorded, since the kernel ignores its address; a connected seqpacket one is
  continued, and the residual is one the agent can choose; a route query to the
  kernel is relayed as the task, so interface enumeration works.
- 2026-10-25, the same section (ADR 0070 (5) amended): at the root
  tiers the restriction rests on the same relay and Landlock as at tier landlock,
  with no kernel program of the run deciding it; the glibc fallback names nscd.
- 2026-10-24, the section "No `net:` section: the host's daemon sockets"
  (ADR 0070): a contract with no `net:` section reaches only
  its own unix sockets and tego's endpoints, rule `host-sockets`;
  `host_sockets: true` restores the old reach.
- 2026-10-20, the one-shot approvals paragraph and R6: a credit names a TCP connect, or a UDP connect or
  addressed datagram (supervisor R13d), as `tego_connect_approved` has
  admitted since 2026-10-19 (`Handle.GrantConnect`
  with proto `udp`, `Handle.GrantDatagram`); its key, the serialization of a
  row's grants and the revoke's untaken report are written down. The text
  said credits are TCP-connect-only and never authorize UDP, which the code
  no longer matched. No behaviour changed.
