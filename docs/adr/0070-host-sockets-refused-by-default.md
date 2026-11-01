# ADR 0070: Host daemon sockets are refused by default; a run with no net: section reaches only its own unix sockets

Status: **accepted 2026-10-24**.
Implemented 2026-10-25 at tier landlock (see Implementation notes): the contract key, compile, `Evaluate`, the
supervisor's connect and datagram relay, the abstract admit, the Landlock half, the record, the conformance cells, the
race test and the cost; the root tiers' kernel half is the root tiers' host-socket work (Decision 5). Amends SEMANTICS §1 (the "no `net:`" row) and §5 (Unix sockets),
agent-contract R19 and R5's merge table, enforce-landlock R6 and R21, supervisor R7, and the record (minor 16).

Amended by [ADR 0128](0128-read-only-route-queries.md): a route query is relayed under a `net:` section too, what is
relayed is read first and only a GET is, and Decision 3's "another netlink protocol stays refused" is refused at `socket(2)`
under a `net:` section, since an unaddressed send was never seen.

## Context

SEMANTICS §1 read a contract with no `net:` section as "deny nothing", for unix sockets as for IP. Such a run could
connect to every unix socket on the host its uid can open: the D-Bus session bus (whose systemd user manager starts any
command outside the run, as `systemd-run --user` does), the Docker, Podman and containerd sockets (root-equivalent for
the rootful daemons), gpg-agent and the SSH agents (they sign with keys the agent cannot read), the X server (synthetic
keystrokes into every other window). R19 only warned, naming the ones it found. It was the one default whose reach
depended on what else ran on the machine, and the one channel the allow-list rule, "anything not named is refused",
did not hold for. Most contracts leave `net:` out; most of the reach they got they never asked for.

## Decision

1. **The unix-only state.** A contract with no `net:` section and no `host_sockets: true` keeps every IP destination
   allowed (`RuleTable.NetUnrestricted`, unchanged), but a unix connect, or an addressed datagram, reaches only a socket
   a process of the run bound and Tego's own endpoints (the runtime's unix: grants: the DNS broker's socket). Every
   other unix destination, pathname or abstract, is refused, reason `net-not-allowed`, rule `host-sockets`.
   `RuleTable.HostSocketsRefused` is the one predicate `Evaluate`, the supervisor and the Landlock builder ask; it is
   kept apart from `NetUnrestricted`, so no IP decision changes. With a `net:` section nothing changes.
2. **The opt-out.** Top-level `host_sockets: true` restores the old reach, all or nothing like `keyring: true`. Across
   `extends` the stricter value wins (`false` over `true`, `true` marked loosening), so only the top-level contract can
   open the host's sockets; a profile's `true` is ignored with `profile-cannot-loosen`. Compile warns `host-sockets`
   at the key, naming each well-known daemon socket it finds and what it gives (docker.sock as root-equivalent), and
   its fix steers to a `net:` section with a `unix:` entry naming the one socket the agent needs (the SSH agent for git
   over ssh, gpg-agent for signing). run_start records the opt-out (`host_sockets: true`).
3. **Race-free at tier landlock, for connect.** The supervisor relays every connect in the unix-only state on its own
   duplicate of the socket (`pidfd_getfd`), with the bytes it copied, never `CONTINUE`: a unix one as the task, on the
   inode its name resolves to (`relayUnix`, supervisor R11, R11a's `boundByRun` deciding whether the run bound it); an
   IP one with the copied address. A sibling that rewrites the address after the copy, or swaps another descriptor in
   with `dup2` after the duplicate, changes nothing the relay connects. An address or socket the supervisor cannot
   read is refused (no `passesUnresolved`). The filter notifies `bind(2)` (enforce-landlock R11c, `unixBinds`), so the
   run's own sockets are recorded. Landlock backs it: the abstract-socket scope from ABI 6 (R7, set whenever the ABI
   has it, as before), and from ABI 9 `RESOLVE_UNIX` handled and granted under every write entry and on the runtime's
   own unix: grants, as under a `net:` section (R21).
   A connect on a socket whose domain is neither IP nor unix (`AF_NETLINK`, `AF_PACKET`, a bluetooth socket) is
   refused `host-sockets`, keyed on the socket's own domain read on the duplicate: the unix-only state reaches no such
   destination, and relaying it from this process would run it with the supervisor's credentials — root at the root
   tiers, where a netlink multicast its uid could not make would pass `netlink_allowed`'s `CAP_NET_ADMIN` check on the
   supervisor (*amended 2026-10-25*). One shape is not refused: a **route query**, an addressed `sendto` or
   `sendmsg` without ancillary data on a `NETLINK_ROUTE` socket (domain and protocol read on the duplicate) to the
   kernel (`nl_pid` 0, `nl_groups` 0), the dump that glibc's `getifaddrs`, `if_nameindex` and
   `getaddrinfo(AI_ADDRCONFIG)`, Go's `net.Interfaces` and libuv's interface list send. It is relayed on the duplicate
   from the copies as the task (`relayRouteQuery`, the kernel seam's `SendToRawAs`: `sys.RunAs` with the task's
   credentials, so netlink's capability checks, made against the sender as well as the socket's opener, are the
   task's at every tier) and recorded allow; a message to another process's port id, to a multicast group or on
   another netlink protocol stays refused (*amended 2026-10-25*: refused, every interface enumeration
   of a contract with no `net:` section failed `EACCES`, Node's `os.networkInterfaces` and Python's `if_nameindex`
   among them, where the text said glibc falls back).
   **Datagrams and stream sends** (part 2): an admitted addressed datagram is relayed on the duplicate from the copies,
   a unix-spelled one as the task to the inode its name resolves to (`SendUnixAs`), any other with the copied bytes; a
   Fast-Open send and a send on a stream socket without a peer are decided like a connect and relayed on the duplicate
   too, so a sibling's `dup2` of a datagram socket over the descriptor and rewrite of the address cannot redirect them
   (*amended 2026-10-25*). An addressed send without `MSG_FASTOPEN` on a connected stream or
   seqpacket socket names nothing the kernel reads (`tcp_sendmsg` and `unix_seqpacket_sendmsg` drop the address,
   `unix_stream_sendmsg` answers it `EISCONN`), so the address is neither decided nor recorded and no line is written,
   as R13a writes none; only the descriptor is guarded (`sendConnectedUnixOnly`, keyed on the duplicate's own domain
   and type): a unix stream send is made on the duplicate with the copied address and without ancillary data, and the
   kernel's `EISCONN` is the answer, nothing sent; an IP stream send goes to the peer on the duplicate with no address
   where the relay reproduces it exactly (no ancillary data, no `MSG_ZEROCOPY`, the payload read whole), and is
   continued otherwise rather than cut at what the supervisor copies; a seqpacket send is continued, since its
   receiver reads the sender's pid in `SCM_CREDENTIALS` (the DNS broker authenticates by it), which no relay from the
   supervisor can give (*amended 2026-10-25*: relayed as a decision, the ignored address was recorded
   as the destination and refused when foreign, a record past 64 KiB was cut, and a seqpacket receiver read the
   supervisor's pid). A send on a socket of a domain the state does not reach is refused as a connect of one is. What
   the relay cannot reproduce exactly (ancillary data, `MSG_MORE` or a corked socket, a payload past what is copied,
   `MSG_ZEROCOPY`), an unaddressed `sendmsg`, a `sendmmsg` batch, and an addressed send on a connected seqpacket socket
   are continued, best effort, run_start cell `host_sockets/datagram`: below ABI 9 (6 for an abstract name) a sibling
   that writes a host socket's name into the agent's memory and `dup2`s a unix datagram socket onto the descriptor
   reaches a datagram receiver (the journal, syslog). The agent chooses the flags, the control messages and whether
   its `sendmsg` names an address, so it can always choose a continued shape: below ABI 9 the cell is a property of the
   tier, not of rare programs, and relaying more shapes would narrow none of what it can reach. Descriptor passing
   (multiprocessing, Ray) sends with no address and is unaffected; an addressed `SCM_RIGHTS` send on a connected unix
   stream socket fails `EISCONN` natively, and does here (*amended 2026-10-25*: this item said such a
   send was what the run's own sockets make and left it continued). The kernel refuses a datagram to a stream or
   seqpacket socket, so no daemon this ADR is about (docker, the session bus, the agents, X11) is reachable that
   way.
4. **The refused line** names the socket (`dst unix:/run/docker.sock`); for a socket on R19's list,
   `agent.HostSocketWhat` gives what it is (`the Docker daemon, root-equivalent`), read from the name the decision was
   made on: the cleaned pathname, resolved against the task's cwd when relative, or the socket the task's walk reached
   (the relay's for a connect, the landed decision's for a datagram; *amended 2026-10-25*),
   with R19's `%U` the invoking user's `/run/user/<uid>` (`config.InvokingUID`, SUDO_UID's at the root tiers, the one
   compile names; *amended 2026-10-25*: it was the address's raw spelling and the supervisor's own uid, so
   `/run//docker.sock`, a relative name and, at the root tiers, every per-user socket got none). reason.Text's sentence for
   `net-not-allowed` reads right for the rule: `Tego refused connect "/run/docker.sock": that destination is not allowed
   in this run (rule host-sockets).`
5. **Root tiers are not changed here.** At tiers cgroup and bpflsm no kernel program of the run decides a unix
   destination for such a contract: the cgroup unix programs and the decision plane's unix hooks hold no row for it.
   A plane narrows only the fs notifications (enforce-plane R22, R27), so connect, `sendto` and `sendmsg` stay
   notified, and the state rests on what carries it at tier landlock: Decision 3's relay, the Landlock scope and
   `RESOLVE_UNIX`, and the same datagram residual (*amended 2026-10-25:* this item first said a plane decides connect
   in place of a notification and admits what such a contract leaves it, which the KVM 6.17 row refuted: its
   fanotify, fmod_ret, lsm and bpflsm axes refuse both conformance cells by the supervisor). It is listed in run_start
   `best_effort` as `host_sockets/root-tier`, in `host_sockets/datagram`'s place, and compile says "best effort at the
   root tiers until they carry a kernel program for it" wherever the run may land there. The root tiers' host-socket work
   attaches the unix programs and plane rows.

Abstract names (part 2): the supervisor records the socket objects a task of the run calls `bind(2)` on with an
abstract name (never the name, which a sibling can rewrite), at most 64, and admits an abstract destination while one
of them holds that name now, asked of the kernel by the socket's identity (UNIX_DIAG_NAME): abstract names are unique
in a network namespace, so a connect to it reaches that socket. A run's own X server (Xvfb) and its own IPC servers
bind abstract names, and refusing them would break runs that never reach the host. Static evaluation (`compile --test`) knows no binds and
refuses every abstract name. Residual: the run's socket may close between the answer and the relayed call, and a
process outside the run bind the freed name in between.

ADR 0113 (not built yet) composes with this one: its built-in refusals hold under a `net:` section and under the opt-out;
under the unix-only state this ADR already refuses those sockets.

## Rejected

- **The R19 deny-list** (refuse the well-known daemon sockets, allow the rest): it misses the next daemon (a new
  container runtime, a vendor's agent socket, a user's tmux server) and holds no line the allow-list rule can
  state. An allow-list of the run's own sockets is closed against what nobody listed.
- **A sixth rule template** for host sockets in the contract: the opt-out is one switch, like `keyring`, and the
  precise form already exists (`net:` with `unix:` entries); a template would be a second spelling of both.
- **Refusing IP when `net:` is absent:** turns the most common contract into `net: {}` and breaks every agent that
  reaches a model or a package index; the unix channel is the one whose reach depended on the host.
- **Relaying every `sendmsg` and `sendmmsg`** (closing the datagram residual below ABI 9): a relay cannot pass
  ancillary data (an `SCM_RIGHTS` array names the agent's descriptor numbers; QUIC's GSO and ECN cmsgs, `IP_PKTINFO`)
  nor write `sendmmsg`'s per-message counts back (I3), so it would refuse Chromium's IPC, HTTP/3 and every batched
  resolver query of a contract that names no network at all, for a residual that reaches no stream daemon and that
  the kernel closes from ABI 9.
- **Continuing IP connects after a family check** (read `SO_DOMAIN`, continue an AF_INET socket's connect): the
  kernel reads the descriptor number and the address again after `CONTINUE`, so a sibling that `dup2`s a unix socket
  over the number, and rewrites the address to a host socket's, reaches it under a line that says IP. Only the relay
  on the duplicate holds both.
- **Relaying a non-IP, non-unix connect or send under the task's credentials** (a `ConnectRawAs`/`SendToRawAs`
  through `sys.RunAs`, as `relayUnix` relays a unix connect) instead of refusing it: it keeps the agent's
  netlink and packet sockets reachable at its own uid and closes the root-tier escalation, but adds a kernel seam for
  a path no contract with no `net:` section needs — the unix-only state's channel is the unix socket, not a raw
  netlink one — and the allow-list's rule ("anything not named is refused") covers a socket family nobody named.
  *Amended 2026-10-25*: adopted for the route query alone (Decision 3), since refusing it failed
  interface enumeration, which a contract with no `net:` section does need (a dev server printing its network URLs,
  psutil); every other netlink destination, `AF_PACKET` and the rest stay refused. The root tiers' host-socket work may revisit
  them if a root-tier workload needs such a socket; the opt-out restores them today.

## Consequences

- Every connect of a run with no `net:` section is performed by the supervisor (OPERATIONS.md: about 6 µs more per
  connect and 8 µs per relayed datagram), and a non-dumpable process of the run (one that set `PR_SET_DUMPABLE` 0, which tier 1
  cannot read) has its connects refused, as under a `net:` section.
- `SSH_AUTH_SOCK`, gpg-agent, X11 and the session bus are refused without `net:`: git over ssh needs a `net:` section
  naming the agent socket (and the hosts it reaches) or the opt-out. glibc's nscd client (`/var/run/nscd/socket`),
  `nss-resolve` and `nss-systemd` fall back to DNS and files when their sockets are refused, so name and user lookups
  keep working; the refusals stay in the ledger (a smoke run shows nscd's twice). Interface enumeration
  (`getifaddrs`, `if_nameindex`, `getaddrinfo(AI_ADDRCONFIG)`'s source-address query) works: its route query is
  relayed, one allow line `dst family(16) proto raw` per query. Another netlink protocol (audit, generic netlink:
  nl80211, ethtool) and an `AF_PACKET` socket are refused `host-sockets`; `host_sockets: true` restores them, a `net:`
  section does not (it refuses a family its rules do not name, unchanged by this ADR, route queries included).
- A run's own servers (multiprocessing, Ray, a local MCP server bound under a write entry) keep working: the run bound
  them.

## Implementation notes

- 2026-10-24: `Contract.HostSockets`, the schema rows, the merge row; `RuleTable.
  HostSocketsRefused`, `HostSocketsOpened`; `decide`'s `hostSocketVerdict`; compile's `hostSocketsReachable` (the
  opt-out warning, the root-tier note) and `agent.HostSocketWhat`; the best-effort cell `host_sockets/root-tier` (and
  `gate.net/unix-connect` only under the opt-out, since the unix-only state relays that connect); the supervisor's
  `compiled.hostSockets`, `decideHostSocket`, `hostSocketsRule`, the connect relay and the refused unreadable
  notification; the Landlock builder's `unixRestricted` (RESOLVE_UNIX, `unixBinds`, the runtime grants' backstop);
  record minor 16 and `run_start.host_sockets`. Tests: `TestHostSocketsUnixOnlyState`,
  `TestHostSocketsRootTierBestEffort`, `TestHostSocketWhat`, `TestHostSocketsWarning`,
  `TestEvaluateNetWithNoNetSection`, `TestEvaluateRunBoundSocketWithNoNetSection`, `TestConnectInTheUnixOnlyState`,
  `TestUnixOnlyStateHandlesResolveUnix`; the tests that pinned the old reach now set `host_sockets: true`.
- 2026-10-24: the integration suites run the old reach under `host_sockets: true`
  (TestIntegrationNoNetSection, TestIntegrationGateNeverRelaysUnixDatagrams) and the default in
  `TestIntegrationUnixOnlyState`; addressed datagrams are relayed (`relayUnixOnly`, `relayUnixDatagram`, the kernel
  seam's `SendUnixAs`), the rest continued under the cell `host_sockets/datagram` (Decision 3; tests
  `TestDatagramInTheUnixOnlyState`, `TestHostSocketsDatagramBestEffort`).
  The abstract admit (`recordRunAbstract`, `runSockets.holdsAbstract`, the kernel seam's `UnixAbstractName`; tests
  `TestAbstractNameInTheUnixOnlyState`, `TestParseUnixDiagName`, `TestIntegrationUnixOnlyState`).
  The refused line's `what` (supervisor `netPayload.What` from `agent.HostSocketWhat`, record minor 16; test
  `TestHostSocketRefusalNamesWhatItGives`) and reason.Text's golden row for rule `host-sockets`. The unix-only
  integration tests run without the abstract scope below ABI 6, where the supervisor alone refuses.
- 2026-10-25 (parts 3 and 4): the capability row `net.host_sockets_refused` (capabilityLine; true at
  tier landlock with a started supervisor); `TestIntegrationUnixOnlyRaceFree`: 10,000 connects, `sendto`s and
  `sendmsg`s while a sibling flips the address between 127.0.0.1, a foreign pathname and a foreign abstract name and
  `dup3`s IP and unix sockets over the descriptor make 0 foreign connections (3,383 under `host_sockets: true`); the
  KVM al2023 6.1 row (Landlock ABI below 6: the abstract name rests on the supervisor alone) passes the unix-only and
  race tests on both boots, and the 6.17 row passes them with the R11a suites; the conformance actor's `connect-unix`
  op and the cells `unix-host-socket-no-net`, `abstract-host-socket-no-net` and `connect-ip-no-net`, which agree with
  the record and `compile --test` on every column (KVM 6.17, both boots: landlock, fanotify, fmod_ret, lsm, bpflsm, each
  refused `host-sockets` by the supervisor); the fixture `host-sockets.jsonl` (`TestHostSocketsFixture`); compile's net
  line and `--json` `host_sockets_refused`; `TestNoShippedContractSetsHostSockets`; `BenchmarkUnixOnlyRelay` (the
  numbers in OPERATIONS.md); Decision 5 corrected (the plane leaves connect notified).
  Departure from the package text: the cells live in their own table `spec/policy/conformance/hostsock.yaml`, not in
  `net.yaml`, because a table holds one contract and net.yaml's has a `net:` section, under which nothing here
  changes. Contract audit (no contract needed a fix): every YAML contract under examples/ and test/poc has a `net:`
  section and is unaffected (kt2, kt5, kt6 and kt7 run those or their own `net:` sections); of the test/e2e scripts
  whose contracts have none, smoke-exec-rules and m0-demo pass offline (m0-demo with nscd's refused connect and
  glibc's fallback); kt1-identity and kt4-ordinary's harness failed the same way before this change
  (kt4: its compile listing names nothing), and kt4's go kind run by hand in the unix-only state builds with no
  refused line (run_start `best_effort` `host_sockets/datagram`, `net.host_sockets_refused` true); kt4's pip and npm
  kinds (a local wheelhouse, a zero-registry package) and kt3's overhead loop use no unix socket by reading;
  test/workloads holds programs, not contracts.
- 2026-10-25: the record standard (spec/record/v1/README.md) documents record
  minor 16; the refused line's `what` is read from the decision's cleaned, cwd-resolved name (`verdictOf.sockPath`,
  the relay's walk's name for a connect) with `%U` the invoking user's runtime directory (`hostRuntimeDirs`); tests
  `TestHostSocketWhatNamesTheSocketReached`, `TestHostRuntimeDirs`. A Fast-Open send and a no-ancillary
  send on a connected stream socket are now relayed on the duplicate (`sendDecisionCtl` clears `continued` for
  `c.hostSockets` and the R13a shortcut yields to a no-ancillary unix-only send), not continued; the connected-stream
  ancillary send stays R13a's CONTINUE, named in the `host_sockets/datagram` residual. The relay is keyed on the
  socket's own domain (`resolveSocket` reads `SO_DOMAIN` in the unix-only state, `hostSocketRelayable`): a connect,
  addressed datagram or stream send on a non-IP, non-unix socket is refused `host-sockets`, never relayed from this
  process. Tests: `TestUnixOnlyRefusesNonRelayableDomain`, `TestUnixOnlyConnectedSends` (as rewritten), the updated
  `TestSendsWithNoNetSection` Fast-Open subtests, and `TestIntegrationUnixOnlyRaceFree` extended with the
  `sendtostream` (MSG_FASTOPEN) and `sendtoconn` kinds (0 foreign arrivals; 267+278 and 886+827 before the fix).
- 2026-10-25: an addressed send on a connected socket in the
  unix-only state is answered by `sendConnectedUnixOnly`, which decides and records nothing about the address: the
  kernel's `EISCONN` on the duplicate for a unix stream socket (ancillary data or not), the payload to the peer on the
  duplicate (`relayToPeer`, which `sendUnaddressed` shares) for an IP stream one it can reproduce, CONTINUE for a
  seqpacket one and for an IP stream one it cannot. Tests: `TestUnixOnlyConnectedSends` (no line naming a connected
  TCP socket's foreign address; a record past `sendBytes` continued, not cut; a foreign name a seqpacket send carries
  continued, not refused; `EISCONN` for a unix stream send with and without `SCM_RIGHTS`) and
  `TestIntegrationUnixOnlyState`'s `nonet_tcp_named`, `nonet_seqpacket_named` (a 100 KiB record arrives whole with the
  sender's pid in `SCM_CREDENTIALS`) and `nonet_stream_named`, which fail at an earlier tip. The race fix: the route query is relayed as the task (`routeQuery`, `relayRouteQuery`, `SendToRawAs`; tests
  `TestUnixOnlyRelaysRouteQuery`, which also keeps another port id, a group, a short address, `NETLINK_AUDIT` and
  ancillary data refused, and `TestIntegrationUnixOnlyState`'s `nonet_interfaces`, Go's `net.Interfaces` in the
  target, which fail with the relay disabled); SEMANTICS §5 says a `sendmmsg` batch on such a socket is continued, as
  `handleSendMMsg` does (the residual). The relay walk's `what`: `TestHostSocketWhatNamesTheRelayWalk`
  (a symlink under a write entry to `/run/docker.sock`, for a connect and a datagram) fails when the relay's `sockPath`
  is dropped, and found that a datagram's line named what its name, not its walk, gave: `landedVerdict` now carries the
  socket the walk reached (`verdictOf.sockPath`), which `decideUnix` keeps. `TestIntegrationUnixOnlyRaceFree`'s proof that the race ran counts the bytes a stream-send kind's peer reads (`countingTCPBytes`), not its
  accepts, which `sendtoconn`'s own connects made, and takes `EOPNOTSUPP` as proof only for `sendtostream` where the
  kernel's Fast Open client is off, never R10's refusal; with the connected IP stream relay replaced by a refusal it
  fails (0 bytes), where it passed before.
