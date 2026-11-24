# ADR 0126: Per-tool MCP rules behind a Tego relay

Status: **accepted 2026-10-27**; built.

## Context

`mcp:` declares servers (a stdio `command` or an HTTP `url`, agent-contract R16a); the supervisor records a stdio
server's start from the exec that launched it, and capture reads an HTTP server's `tools/call`
(`internal/runtime/derive/mcp`). Nothing can say "this server, but not its `delete_repository` tool": a server is all
or nothing, and a stdio server's messages pass through pipes no Tego component reads.

Constraints: the layering rule (pure decision cores in `internal/check/*`; the dashboard holds no authority; features
are services with stated seams); no model-based judging anywhere in Tego; the agent-reachable paths are fixed by R6a
(`~/.tego`, the ledger root and `/run/tego` are read- and write-denied to every run at an enforcing tier, except a
ledger root that also holds what the run needs, which compile leaves readable and warns `ledger-readable`) and
ADR 0070 (a run reaches no host unix socket it did not bind unless `host_sockets: true`).

## Decision

### 1. Contract syntax

```yaml
mcp:
  - name: files
    command: [python3, /opt/fake-mcp/server.py]
    tools:                         # new key; absent = today's behaviour, no relay
      allow: [read_file, list_dir] # present: every tool not listed is denied
      deny: [delete_file]
      ask: [write_file]            # held for a person on the run's broker (needs the contract's ask: section)
```

- `mcp[].tools` is a mapping of three optional lists of exact tool names (`^[A-Za-z0-9_.:/-]{1,128}$`, MCP's own
  name rule widened by `:` and `/` that real servers use). A name in two lists is a schema error. `tools: {}` puts
  the server behind the relay with nothing restricted, which is how a person gets live switches without writing a
  rule. A non-empty `ask` needs the contract's `ask:` section (the broker exists only then). `tier: observe` is
  refused (the relay needs an enforcing tier to keep the agent from going around it).
- `tools` is canonical contract bytes (part of `contract_hash`); a contract that does not write it hashes as before.

### 2. `credentials:` is refused

Compile refuses a contract that writes `credentials:`, naming each entry and the variable to pass instead.

### 3. The forwarder's headers

The forwarder passes every header on as the agent sent it.

### 4. The MCP relay

- **Policy core** (`pkg/policy/mcptool`, pure): `Decide(rules, overlay, server, tool)` returns allow, ask or deny
  and the rule that decided: a live overlay entry for the tool wins (rule `mcp[<s>].live[<tool>]`); else
  `tools.deny` (`mcp[<s>].tools.deny[<tool>]`), `tools.ask` (`…ask[…]`), `tools.allow` present and the tool absent
  (`mcp[<s>].tools.allow`, denied: not on the list), else allowed (`mcp[<s>].tools.allow[<tool>]` or `mcp[<s>]`).
  `FilterToolsList` removes denied tools from a `tools/list` result (asked ones stay visible); `Refusal` builds the
  JSON-RPC error `{"jsonrpc":"2.0","id":<id>,"error":{"code":-32001,"message":"Tego refused the MCP tool <tool> on
  <server>: <why>","data":{"tego":{"rule":…,"reason":…}}}}`. Exact names only: no globs, no model.
- **Launcher side** (`internal/runtime/mcprelay`, a `source.LoopbackSource` in a new `Deps.Extra` list, so it is
  neither a capture nor an observe source): one TCP control listener on `127.0.0.1:0` for stdio shims and one HTTP
  relay listener per `url` server with `tools`. Both ports are admitted to the run through `Endpoints()` like the
  forwarder's. `Vars()` gives `TEGO_MCP_RELAY=<control addr>` and `TEGO_MCP_CONFIG=<runtime dir>/tego-mcp.json`, a
  file in Claude Code's `mcpServers` shape naming, per relayed server, `{command: <tego>, args: [mcp, relay, --server,
  <name>, --, <declared command…>]}` or `{type: http, url: http://127.0.0.1:<port><path>}`.
- **Stdio shim** (`tego mcp relay --server <name> [--run <id>] -- <command…>`, run by the agent's MCP client inside
  the run): connects to `TEGO_MCP_RELAY`, says hello `{v, server, argv}`; the service admits it only when the TCP peer
  is in the run's cgroup subtree, its image is the launcher's own `tego` executable (dev and inode of
  `/proc/self/exe`) with argv `… mcp relay …`, the server is declared with `tools`, and argv after `--` equals the
  declared command. The shim prepares the fresh release socket and exact stage argv with the service before starting its
  waiting `__mcp_server` child over AF_UNIX sockets. A constrained `mcp relay *` grant needs no broader user
  permission: only that fresh-socket child can receive the conditional runtime stage grant. The shim reports the child's
  PID and waits for the service to pin it with a process pidfd and acknowledge it before releasing it to exec the
  server in place. A private close-on-exec control socket reports exec completion or failure; only then does the shim
  send `Started`. A failed registration closes the admitted connection before killing/reaping the waiting child,
  so a delayed registration cannot pin a reused PID (*amended 2026-11-03*, SEC06 and compatibility follow-up; protocol v3,
  v1/v2 refused). The server channels are socket pairs it alone holds (not pipes: a pipe
  can be opened again through `/proc/<pid>/fd/N` with no ptrace attach, and a socket cannot) and is a byte pipe that forwards
  nothing on its own: every client line goes to the service, which answers `to_server` (allowed), `to_client` (a
  refusal) or holds it (ask); every server line goes to the service, which passes it (filtering the result of a
  `tools/list` the client asked). What `to_server` carries is the client line in one wire form, never the agent's
  bytes: compact JSON with U+0085, U+2028 and U+2029 as escapes, which is also what the relay reads to decide. A line
  that is not one JSON value in UTF-8 is answered -32700 and not passed (*amended 2026-11-01*: the raw line used to be
  forwarded, so a server ending lines at a lone CR read a denied call out of a line the relay read as one `ping`). Such a
  line, and a client line past `MaxLine` that the shim dropped, is one `mcp` line, refused, rule `mcp[<name>].relay`, reason
  `mcp-tool-denied`, no tool (*amended 2026-11-01*: it may have been a call, and the record had no trace of it; the line past
  the bound got no answer either). If the control connection drops, the shim kills the server and exits non-zero.
- **The gate** (`internal/runtime/supervisor`, new `Options.MCPRelayed`): an exec the supervisor already names as a
  declared server's start (`mcpServerOf`) for a server with `tools` is allowed only for the exact child registered by
  its admitted shim before release to exec. The service opens the child's pidfd while it waits, verifies its parent
  at registration and the shim's admission again, then retains the pidfd until the one start is consumed or the
  connection ends. At the gate the registered PID must match and the pidfd must still name a live process; no
  parent-PID lookup authorizes an exec. An unrelated child cannot consume the pending start, and a dead child or
  unreadable/closed pidfd fails closed. Otherwise the exec is refused, rule `mcp[<name>].relay`, reason
  `exec-not-allowed` (*amended 2026-11-03*, SEC06). An
  argv the supervisor could not read whole names no server but may still be the declared start, since a fault stops its
  read and not the kernel's copy: when the part read could be a declared vector the relay is asked of each such server,
  and without its word the exec is refused, by that server's rule, or `args-unreadable` when several could be it. A NULL or empty argv reads as `[""]`, as the kernel gives it, so it is the
  start of a server declared with no arguments (*amended 2026-11-01*).
- **HTTP** (`url` servers with `tools`): compile no longer derives the `net.allow` entry for the URL (agent-contract
  R16a's derived rule). Under a `net:` section that does not itself admit the URL, the agent's only route is the relay.
  With no `net:` section every destination is admitted, the URL included, so the agent can reach the server around
  the relay; compile warns (`unenforced`). The relay admits the peer as the forwarder does,
  decides each JSON-RPC message of a POST body the same way (a batch is decided member by member, *amended 2026-11-21*,
  "Amendment 2026-11-21" below; *amended 2026-11-01*: a body refused unread, or one past 4 MiB, is recorded as
  such a stdio line is, one `mcp` line under rule `mcp[<name>].relay`), filters `tools/list` in a JSON or SSE response, and forwards the rest over
  TLS (http for an `http://` URL) to the declared URL. An event stream from the server, a GET's too, is read by
  whole events and every answer in it with a tools array is filtered (*amended 2026-11-21*). Only a POST body is decided, so a request by any other method that carries a body is
  refused 405 with an `mcp` line under rule `mcp[<name>].relay`, and never reaches the server (*amended 2026-11-01*:
  such a body used to be forwarded undecided).
- **Ask.** A held call is an `ask.Request{Op: "mcp_tool", Target: "<server> <tool>", Rule, Hold: "request", PID,
  TID}` on the run's broker (configured through a new `ConfigureMCPAsk` beside `ConfigureAsk`), so it appears on the
  Approvals page and `tego ask` with Allow once / Deny; the decision is the broker's, recorded by the broker's own
  ask and answer lines. Only the asking call waits: other messages keep flowing.
- **Live both ways.** Overrides live in the run's `<ledger_root>/<run>/mcp-tools.json` (new leaf
  `internal/mcptools`: format, `Update` under a lock file by atomic rename, `Read`, `Stat`), which the agent cannot
  write. The service polls it every 500 ms and on every `tools/call`, and writes one gap line per change it put in
  force. Tightening (to Deny, or Allow to Ask) applies at once, to a call held for a person too: an approved call is
  decided again, and a Deny put in force during the hold refuses it, rule `mcp[<name>].live[<tool>]`. Whether a change
  loosens is decided again on the overlay under the writers' lock, so a Deny that lands after the preview's read is not
  undone by a change nobody acknowledged; loosening needs the preview-bound acknowledgement on
  the dashboard and `--yes` or a typed confirmation on the CLI, and is refused from inside any run. On a Locked run a
  switch to a decision looser than the contract's is refused by every writer (*amended 2026-11-11*, "Amendment
  2026-11-11: Locked runs" below; docs/GAPS.md C39).
- **Tools seen.** The service writes `<run dir>/mcp-seen.json` (`{server: [tool names]}`, at most 512 a server,
  names as above) from each `tools/list` result, so the dashboard can show a switch for a tool nobody has called.
- **Record.** Each `tools/call` decision is an `mcp` line, source `proxy` (Tego's own in-path relay), payload
  `{name, transport, tool}`, verdict `allow` (authority `rule`, or `human` after an approved ask) or `refused` with
  reason `mcp-tool-denied`, or the broker's `ask-denied`, `ask-timeout`, `ask-unavailable`. A live change is a gap
  `what=enforce`, why `mcp-tool-changed`, with `mcp_tool {server, tool, decision, by, serial, at}`.

### 5. Record revision

One revision, `record_minor` 25, holds the record fields below:

- `mcp` lines may be written by source `proxy` with verdict `refused`, new reason `mcp-tool-denied`, rules
  `mcp[<s>].tools.*[…]`, `mcp[<s>].live[…]`, `mcp[<s>].relay`;
- `gap` lines may have why `mcp-tool-changed` and carry `mcp_tool`.

Below it each of those is refused `[below-minor]`. Nothing is written on every run, so a ledger at the revision with
no such line relayed nothing. The reason joins `spec/reason/REASON-CHANNEL.md`, `pkg/spec/reason` and the dashboard's
words.

### 6. Services the pages call

| Page | Service (holds the logic) | Store (leaf) |
|---|---|---|
| MCP tools (`/mcp`, nav "MCP tools") | `internal/control/mcpact`: `State(run)` (servers, transport, relayed or not, tools seen ∪ contract ∪ overlay ∪ ledger, the decision and its source, calls/refusals/asks per tool), `Plan`/`Set` (ack for a loosening), `Reset` | `internal/mcptools` |

The web package parses forms, renders and calls these; it never opens the overlay itself. The CLI
uses the same leaves through the same rules. The pure decision lives in `pkg/policy/mcptool` (no I/O, no clock), since
the import-direction tests forbid `internal/runtime` → `internal/check`.

## Security argument

**The relay.** (1) Decisions are made in the launcher, outside the run, from the contract and an overlay the agent
cannot write; the in-run shim is Tego's own static binary, and it forwards only what the service says. (2) The gate
refuses a stdio server's declared start unless it is the admitted shim's pre-registered, pidfd-pinned child. An HTTP
server's URL gets no derived network grant; direct access is refused only when the run's `net:` rules do not admit
that URL. Neither property denies the attach authority described in C50. Admission proves a
process holds the connection's socket, not that it wrote the hello, so the gate looks again as the server starts: the
parent is the admitted process by its start time, with tego's image and the shim's argv, holds the admitted socket with CLOEXEC set, and
holds no other TCP socket. The shim's own dial sets CLOEXEC; an inherited descriptor cannot retain it across exec,
so it cannot register a forged child before the shim has dialled its real connection (SEC06). A shim dials one connection, so a shim the agent started with the socket inherited and a
listener of its own in `TEGO_MCP_RELAY` shows up as a second one, and a pending start an open connection kept past the
shim's death fails the start time. (3) A held call waits for a person on the broker the Approvals page
answers; loosening needs an acknowledgement bound to its preview and is refused from inside a run. (4) Every
decision is a ledger line.
*Amended 2026-11-01:* the gate holds at every tier. Where a plane decides a run's execs, tier bpflsm and tier cgroup in
a plane mode, the supervisor's fast handover used to return before the gate, so an unrelayed start was recorded and
ran. A running relay now costs the run that handover, as command rules do, and what continues keeps its kernel line.
*Residuals:* an HTTP server is kept to its relay only under a `net:` section that does not admit its URL (with no
`net:` section compile warns that the agent can reach it around the relay); the gate recognises the declared command line exactly (the rule that already names a server's start),
so another spelling of the same server is not the server (deny it with `exec.deny`); with Yama `ptrace_scope` 1 or 0 the
agent can ptrace the shim it started, or take its descriptors with `pidfd_getfd`, and write to the server's socket: both
need ATTACH, and a `tools:` server whose run allows that is not protected from it. The fork-then-exec pending-start
theft is closed by pre-exec registration of the exact child and its retained pidfd (SEC06/C51); this adds no attach
or socket-copy denial (C50). A server that opens `/dev/stdin` by
name fails, ENXIO, since its stdin is a socket; `tools/list` filtering is a courtesy, the
enforced thing is `tools/call`; a server that offers the same capability under an allowed name is allowed.

## What this does not cover

- Per-argument MCP rules ("read_file only under /src"): names only.
- Saving a live MCP switch into the contract: the switch lasts for the run; Change rules writes the contract.

## Consequences

- A contract that writes `credentials:` is refused at Compile (§2). An agent holds its own key, passed with `env.pass`.
- `run_start.record_minor` rises on every run (the only change on the option-off path); a contract without
  `mcp[].tools` runs exactly as before: no relay, no gate, no new lines.
- `tego` and `tego-control` are rebuilt together; runs started by an older `tego` do not relay.
- `docs/adr/README.md`, `spec/record/v1`,
  `spec/reason/REASON-CHANNEL.md`, `docs/DASHBOARD.md` and `docs/user/mcp-tools.md` describe it.

## Amendment 2026-11-01: the nav

The dashboard's side nav no longer lists MCP tools by default. It is left out unless `tego-control serve --preview` is
given, so a first-time reader sees only the pages that work for every run. The page itself is unchanged and answers at
`/mcp` as before; a link to it still opens it. Where this record says "the nav's" link or item, read "the nav's, with
`--preview`". docs/DASHBOARD.md ("Start it") holds the flag.

## Amendment 2026-11-11: Locked runs

§4 planned a Locked check; until now it was not built, so `tego mcp allow` and the MCP tools page could loosen a
Locked run while it ran (docs/GAPS.md C39). Built:

- **Who checks.** Both writers: `tego mcp allow|ask|deny|reset` (internal/cli/mcp.go) and `internal/control/mcpact`
  (the MCP tools page's `Plan`, `Set` and `Reset`). Each reads the run's live mode from its run_start
  (livestatus.Facts.Adjustable, through `runact.CheckLoosening` for the page) and refuses with
  `liveblock.CheckLoosening`, which returns `liveblock.ErrLocked` in the sentence a lift of a Locked run gets: on the
  terminal "`<run>` is Locked: it keeps to its contract while it runs, so nothing loosens until its next run", with
  the lift's hint and code `[locked]` (record.LiveRefusedLocked), exit 1; on the page "Not done: this run is Locked:
  loosening applies from its next run." (the same constant as a refused lift), on the flash and on the preview, which
  then has no acknowledgement to confirm, only a link back. The shared sentence named the kernel ("the kernel holds it
  to its contract") until this amendment's review; it names no mechanism now, since the relay, not the kernel, holds a
  tool switch, and it is the same for `tego lift`, `grant` and `restore`.
- **What it refuses.** A switch whose result is looser than the contract's own decision for the tool (deny to ask or
  allow, ask to allow). This follows ADR 0125's Locked promise, "never looser than its contract while it runs", as the
  other live writers keep it: a Locked run takes a live block (a tightening) and its removal (back to the contract),
  and refuses a lift. So a tightening is taken, and so is a reset or a switch back to the contract's decision; that
  one still needs its acknowledgement when it loosens the run from now. The contract and the change decide it, not
  the overlay, so the writers' lock has nothing more to decide.
- **Fail closed.** A run below record minor 26 (or one that names no fence) counts as Locked. A run whose run_start
  is not written yet (no events file, an empty one, or a first line still being written) is refused too, as still
  starting (`liveblock.ErrStarting`, `[starting]`: "try again in a few seconds"), never as Locked: a launcher holds
  its run a few seconds before it writes run_start, and an Adjustable run was refused as Locked in that window
  (*amended 2026-11-11*, acceptance 2B). A complete first line that does not decode, or is not run_start, is refused
  as not readable (`liveblock.ErrStartUnreadable`, `[start-unreadable]`), with no "try again", since waiting does
  not change it (*amended 2026-11-11*, second review). A run no launcher holds gets the writers' not-running refusal first,
  as `liveblock.CheckFence` orders it: `liveblock.CheckLoosening` refuses it `ErrNotRunning` itself, so a free lock is
  never a go-ahead, and the page's preview of such a switch is refused too, with no acknowledgement; a lock that cannot
  be probed counts as held.
- **Record.** A refusal writes nothing: no overlay change and no ledger line, as a writer's refusal of a lift writes
  none (ADR 0125 decision 5: lines come from what took effect). No record field changed.
- **Not covered.** ~~The relay applies whatever `mcp-tools.json` holds and does not read the mode. A switch written there
  some other way (an older `tego`, or a same-user process outside every run writing the file) still loosens a Locked
  run, with its `mcp-tool-changed` line. Refusing it in the relay needs a record shape for that refusal, so a record
  revision; not built (GAPS C39, narrowed).~~ *Closed 2026-11-21* without a record revision: the relay reads the mode
  ("Amendment 2026-11-21" below, "The Locked consumer").
- **Consequence.** At tier landlock every run is Locked (Adjustable is refused there, ADR 0125 decision 7), so live MCP
  loosening is gone at landlock; it stays on Adjustable runs at cgroup and bpflsm.
- **Verified** (on this host, as a user, 2026-11-11): unit tests in liveblock (`TestCheckLoosening`), runact
  (`TestCheckLoosening`), mcpact (`TestLockedRunRefusesLoosening`, `TestLockedRunAcrossAnUnreadableStart`,
  `TestEndedRunRefusesLoosening`, `TestAdjustableRunLoosens`), internal/cli (`TestMCPSwitchRefusedOnALockedRun`) and web
  (`TestMCPLockedRunRefusesLoosening`); `test/e2e/mcp-tools-e2e.sh` at tier landlock (the Locked refusal by CLI and
  dashboard, the tightening, and a second, Adjustable run through the test build's `TEGO_TEST_LIVE_ANY_TIER` hook
  that takes the allow live). With the checks removed (`go test -overlay`, `go build -overlay`) the new tests and 10
  of the e2e's checks fail. Not verified: a root tier (an Adjustable run at cgroup or bpflsm) in a guest.

## Amendment 2026-11-21: batches, listings, the HTTP holder and the Locked consumer

One rule: **a governed agent reaches only the tools the contract and the person's
approvals allow, and no message rides on another's decision.** No record field, reason, rule, line shape or revision is new
(`record_minor` stays 41); what each change writes is said below.

- **A batch is decided member by member.** The all-or-nothing answer of §4 (a batch holding a refused or held call was
  answered with an error for every member, the allowed ones included) is replaced. Each member of a JSON-RPC batch, from a
  stdio line or a POST body, gets its own decision, as a single message does:
  - a `tools/call` is allowed, denied or asked by the rules; a call the relay cannot name is refused by `mcp[<s>].relay`;
  - every other member (a notification, another request, the client's own response) passes;
  - a request whose id another request of the batch also has is refused, with every request of that id, by
    `mcp[<s>].relay` ("another message of this batch has the same id"): two answers under one id could be told apart by no
    client, so a refusal could be read as the allowed call's result. Ids compare as the JSON the client sent (`1` and `"1"`
    differ); a notification has none;
  - the members that pass go on as a batch of their own members (a batch of one stays an array); each refused member that
    has an id is answered with an error of its own, in one array, at once; a refused member with no id has no one to answer
    and is recorded all the same; a member that is asked is held as a single call is (stdio: on its own goroutine, and it
    goes on alone, as the one message it was, when a person approves it; HTTP: all the batch's asks are put together, since
    the one answer waits for all of them) and an approval is decided again against a Deny that landed meanwhile;
  - every refused member is one `mcp` line (rule and reason of its own), and every allowed call one allow line, as for
    single messages. A batch of more than **128** members (`MaxBatch`) is refused whole and unread: one `mcp` line under
    `mcp[<s>].relay`, one error with no id (code -32600), nothing sent on; a batch with a member that is not a message is
    refused whole as an unreadable line is (-32700, one line).
  - On HTTP the one answer carries both: the server's JSON array gets the refusals as more members; an event stream gets
    them as its first event; a server that answers 202 (the passed members were notifications) is replaced by a 200 with
    the refusals; an answer that is not JSON or an event stream, or a JSON that is not an answer, is not passed on and is
    a 502 with a line of the record (the refusals could not be added to it). A server's own error status passes as it
    came, and the refusals ride nowhere then: the whole POST failed and nothing it held ran. On stdio the refusals and the
    passed members are two frames (the client sees two arrays); clients match answers by id.
- **Listings are filtered however they were asked.** An answer that has a `result` with a `tools`
  array is filtered by that shape, **whatever its id is** (one spelt 1.0 for 1, one no request waits on, none at all), in a
  batch answer, in an event stream and in a JSON answer whose type is spelt in any case or as `+json`. The relay asks the
  server for the answer as the relay reads it (`Accept-Encoding: identity`, whatever the client accepts); an answer in another
  `Content-Encoding`, and a tools/list's answer that is not JSON or not an event stream, is not passed on (502, one line of
  the record). An event stream is read by whole events as a client reads them (lines end at LF, CR or CRLF, the `data:` lines
  of an event are one message joined by LF), so a message spread over several lines is filtered; the other fields of an event
  pass; a message that is not complete JSON passes, except that when a tools/list was asked it is dropped and recorded. This
  holds for a GET too (a resumed stream replays answers). Ids are values (`idKey`): 1, 1.0 and 1e0 are one id, "1" another.
  On stdio the relay remembers the ids of the requests it passed until their answers come, and refuses a request whose id
  is still waiting (a call's answer would take a list's entry, and no client could tell the two answers apart), or past 1024
  waiting, with an error of its own and a line of the record: the filter does not rest on this table.
- **The HTTP holder.** An ask of an HTTP client is placed on the process that holds its connection. The search lists
  the descriptors of the run's own processes only, in the cgroup the socket was made in and then the run's. A process that
  hides its descriptors from its own user (`PR_SET_DUMPABLE 0`, which hardened agent CLIs set) used to be missed, so every
  ask it made was refused `ask-unavailable`. It is now placed **by exclusion**: no process whose descriptors could be
  read holds the socket, and exactly one process hides them, so the socket is that one's (admission proved the peer is in
  the run by the socket's cgroup). With two such processes, or one whose descriptors could not be listed for another
  reason, no process is named and the call is refused `ask-unavailable` and recorded, as before: a pid is never guessed.
  A connection whose holder could not be named is not searched for again by its next calls for 2 seconds. A placement by
  exclusion is kept only while that process still hides its descriptors. Asks waiting for a person are bounded for the whole
  relay at 128 (`MaxBatch`), across batches and calls: the call past it is refused `ask-unavailable` and recorded. A refused
  call that has no id (a notification) is recorded and gets no error. The residual of
  exclusion: a socket handed (SCM_RIGHTS) to a process outside the run's cgroups, while the run has one process that hides its
  descriptors, is named as that process; the call is still the run's by the socket's cgroup, and only its card's pid is
  wrong (the broker re-checks the pid is in the run). The same holds for a child that another user's or `sudo`'s run makes
  hidden, and for a process in a nested pid namespace, which `cgroup.procs` does not list, so a hidden process beside it can
  be named in its place: attribution inside the run, never a decision. A socket held by no process in either cgroup (its holder exited) is the refusal above.
- **Admission reads the kernel once.** A peer's socket is placed by one exact `sock_diag` lookup
  (`peer.TCPSocketInfo`: its cgroup and its inode, the dashboard's lookup), not by a read of `/proc/net/tcp` row by row,
  in the stdio shim's admission and the HTTP holder; the table is the fallback where the kernel has no TCP socket
  diagnostics or the lookup fails, and an error is never an admission. An HTTP connection is admitted once and keeps its
  socket's lookup and its holder for its later requests (a start-time read and at most one descriptor listing each, not a
  new search); a descendant cgroup is found by one walk of the run's own subtree and kept. Left as it was: the gate's check
  of an admitted shim (`procStillShim`) reads the shim's own network namespace's TCP table once per server start, to prove
  the admitted socket is the only TCP socket it holds; it is per start, not per connection or per call.
- **The Locked consumer.** The relay and the model forwarder read the run's mode: `mcprelay.Options.Adjustable`
  and `forwarder.Options.Adjustable`, set from the compiled table (`RuleTable.Adjustable`, the contract's `live.mode`)
  where the launcher builds them. **The zero value is Locked**: a caller that says nothing never gets the Adjustable
  behaviour, and the mode is the launcher's in-process fact, which no file in the run's folder (and so no change of one
  mid-batch) can move. On a Locked run:
  - an overlay entry looser than the contract's own decision for the tool (`mcptool.WithinContract`: deny to ask or allow, ask
    to allow, by the writers' own comparison, `mcptool.Loosens`) is not in force, whoever wrote it; one that tightens is, as
    a live block is. A tool is decided by the contract, or by the tighter switch, for every call, listing and ask.
  - A model route other than direct is not in force; the endpoint stays on its own backend.
  - Each held switch or route has a line, on the first read of the overlay too (a run starts with the overlay it finds): the
    **existing** `mcp-tool-changed` line with decision `reset` (the contract decides the tool, which is what is in force)
    and the author's `by` followed by `HeldByLocked` ("... (not in force: the run is Locked, so the contract decides this
    tool)"); the existing `model-route-changed` line with route `direct` and the author's `by` followed by the forwarder's
    `HeldByLocked`. Each call the held switch would have let through is refused by the contract's rule with its own `mcp`
    line, so the ledger never shows a loosening that did not happen. An overlay that cannot be read leaves the contract (or
    the last tightening read) in force, as it does for an Adjustable run, so it never reads as an open door.
  - The MCP tools and Model routes pages (mcpact, routeact `State`) show what the relay and forwarder decide: for a run whose
    run_start does not say it is Adjustable (Locked, still starting, or unreadable) the contract's decision or route, not a
    held switch.
  - **What an older reader sees:** the same two lines it read before. The held line is an `mcp-tool-changed` of decision
    `reset` or a `model-route-changed` of route `direct`, each with a longer `by`, which no reader checks (`by` and `at` are
    free text); a reader of an older launcher's record reads a reset or a revert, which is what is in force. A newer
    launcher's Locked run's record carries no line an older verifier refuses. An older launcher (older `tego`) neither
    reads the mode nor writes these lines, and keeps the behaviour of the 2026-11-11 amendment: only its writers refused.
- **Not covered.** A `tools/call` notification (no id) is a call the shared reader does not name, so it is refused by
  `mcp[<s>].relay`, not by the tool's own rule. A batch's refusals on stdio and the passed members are two frames, not one
  array. A member's refusal does not stop an id reused across two separate messages (the client's own bookkeeping).
  Duplicate ids are refused only among the requests of one batch. Root-tier and multi-user guests were not run
  (`docs/GAPS.md` C39 lists what remains).
- **Verified** (this host, as a user, 2026-11-21): `internal/runtime/mcprelay` (`TestBatchMembersAreDecidedOnTheirOwn` and the
  batch tests, `TestBatchedToolsListAnswerIsFiltered`, `TestToolsListWithOneIDTwiceIsRefusedTheSecondTime`,
  `TestManyRequestsInFlightAreRefusedPastTheBound`, its review tests, the HTTP listing and merge tests, `TestHTTPAskPlacesAClientThatHidesItsDescriptorsByExclusion`
  and its refusals, `TestHTTPConnectionSearchesForItsHolderOnce`, `TestPeerSocketInodeTakesTheExactLookup`,
  `TestRealProcsTellAHiddenProcessFromOneThatHoldsNothing` with a real process that is not dumpable,
  `TestLockedRunHoldsLooseningSwitchesOutOfForce` and its start, unreadable-overlay, mid-batch and HTTP cases),
  `internal/runtime/capture/forwarder` (`TestLockedRunKeepsTheEndpointOnItsOwnBackend` and its siblings),
  `internal/control/mcpact` and `routeact` (the page's state), `internal/platform/peer` (`TestTCPSocketInfoNamesTheSocketByItsInode`),
  `pkg/policy/mcptool`. The tests of a changed behaviour (34 of the relay's, 4 of the forwarder's, 2 of the pages', 2 of the launcher's wiring) fail with the old source behind the same names
  (`go test -overlay`); the helpers that are new in this change (the real-`/proc` view, the cgroup walk, the socket-diag parse,
  `WithinContract`) have no old source to run against.

## Amendment 2026-11-21: the secret-holding launcher is not dumpable

Closing the SHOULD that §2 left open ("the launcher is not made non-dumpable"). One rule:
**every Tego process that holds a secret sets `PR_SET_DUMPABLE 0` before the secret enters its memory and keeps it there.** A
process of the same user, the agent included, then cannot read that memory through `/proc/<pid>/mem`, `process_vm_readv` or
`ptrace`, nor its environment or descriptors through `/proc/<pid>/environ`, `/proc/<pid>/fd` or `pidfd_getfd`. No record
field, reason, rule or line is new (`record_minor` stays 41).

**Why it matters on a default host.** With Yama `ptrace_scope` 1, a process cannot attach to its parent, so `mem` was closed to
the agent; `environ`, `fd` and `fdinfo` are opened in the read mode, which Yama does not gate, and were open to any process of the
user (measured: a child and a sibling of a dumpable process read its `environ` and `fd`; `TestMakeUndumpable`
fails without the hold). The launcher's environment is the one the person typed `tego run` in, whatever the contract's
`env.pass` gave the agent. With `ptrace_scope` 0, `mem` and `ptrace` were open too, which is the residual §3 named.
The processes that gained are the ones outside the run (any program of the user, a build step, an editor plugin) and an agent that
runs under no Landlock domain (`tego watch` with no `--boundary`, `--observe`): inside an enforcing tier every Landlock domain
already refuses `ptrace`, `process_vm_readv`, `/proc/<pid>/mem` and the read-mode files of a process outside its own domain
(`security/landlock/task.c`, docs/ARCHITECTURE.md), and the supervisor refuses the agent's `pidfd_getfd` (`handlePidfdGetfd`); a guest
probe (below) measured what a governed agent at tier landlock gets from each of its ancestors, the launcher among them.

**Who holds what, before and after** (every Tego process that started in this tree, read from the code):

| Process | Holds | Before | After |
|---|---|---|---|
| `tego run`, `tego watch` (the outer process and the re-entered `__user_scope` one) | the caller's whole environment, and the saved logins `run` adds to it | dumpable | undumpable from the dispatch (the re-entered process, before it reads the request that carries the environment) |
| `tego adopt` | the adopter's environment | dumpable | undumpable |
| `tego start`, `tego setup` (the guide) | a token or key a person types or `claude setup-token` prints, the saved logins | dumpable | undumpable |
| the reaper, the adoption reaper, the linger timer, the ring trimmer, the probe remover | nothing: an environment of `PATH` alone, no config, no ledger home | dumpable | unchanged: it holds nothing |
| the open deputy | nothing of the person's (it walks paths); undumpable since ADR 0041 | undumpable | unchanged |
| the child stage and the agent | the agent's own environment (`env.pass`); out of scope: the stage sets `PR_SET_DUMPABLE 1` for `pidfd_getfd`, and the agent keeps its own debugging | dumpable | unchanged |
| `tego-control serve` (the dashboard) | the sign-in token, the CSRF key and the acknowledgement keys | dumpable | undumpable since 2026-11-22 (ADR 0100 (7), amended 2026-11-22; closed below) |

The hold is `Command.HoldsSecrets`, set on `run`, `watch`, `adopt`, `start` and `setup`; `runCommand` makes the process
undumpable before it reads a flag and refuses to run the command (exit 125, `[undumpable]`) when it cannot
(`sys.MakeUndumpable` sets the flag and reads it back). `TestSecretHoldingCommandsAreExactlyThese` holds the set exact, so a new
command decides which side it is on. An exec makes a process dumpable again, so every helper the
launcher starts is dumpable until it chooses otherwise, and none holds a secret.

**Readers of a launcher's `/proc`, each checked against a real undumpable process.** An undumpable process keeps `stat`, `status`,
`cmdline`, `cgroup`, `comm`, `mountinfo`, `limits` and the `task/*/stat` files readable and hides `environ`, `mem`, `maps`, `fd`,
`fdinfo`, `exe`, `cwd`, `root`, `ns/*`, `io` and `syscall` from a caller without `CAP_SYS_PTRACE` (measured for a caller that is not root, on Linux 6.12, 6.17 and 6.19; a root caller that lacks only `CAP_SYS_PTRACE` is refused `environ`, `maps` and `auxv` on 6.12 and reads them, with `smaps_rollup`, on 6.17 and 6.19); `pidfd_open`, `pidfd_send_signal`
and polling a pidfd need none of it, and `pidfd_getfd` and `ptrace` are refused. Its own reads of `/proc/self` are not affected
(`/proc/self/fd`, `exe`, `ns/*`, `cgroup`, `status`, `mountinfo`, `loginuid` and `uid_map` open; `auxv` does not, and
`config.AtSecure` already reads the runtime's copy first; `oom_score_adj` cannot be written, and only the exec'd reapers write it).

| Reader | What it takes from the launcher | Result |
|---|---|---|
| `tego status`, the dashboard's run chip, `tego pause`, `resume`, the sweep (`runlock.LauncherCheck`) | the lock line's pid and start time (`stat`), a pidfd, and the proof that the pid holds the run's flock | works. Where `/proc/locks` prints the device `stat` shows (ext4) the exact row proves it. Where it does not (a btrfs subvolume) a caller that signals only itself takes the row on the superblock device of the mount that holds the lock file (below); any other caller without `CAP_SYS_PTRACE` reads the launcher Unknown, never Gone, in words that say so (`runlock.UnknownRecovery`). A caller with `CAP_SYS_PTRACE` reads the descriptors. |
| `tego stop`, the dashboard's Stop, `tego ask`, `approve`, `deny`, the dashboard's answers (`runlock.OpenStopTargetFor`, `askclient.Launcher`) | the same, and a pidfd to signal | the same; a refusal says that the launcher's descriptors are hidden and that a caller with `CAP_SYS_PTRACE` (root, unless a container or a service unit drops it) reads them (`hiddenLauncherWhy`), and is never "not running" |
| the global lock table | a read of `/proc/locks`, which is paginated: a lock taken or dropped meanwhile can leave the held row out of one read | read up to four times, 3, 6 and 9 ms apart, for a launcher whose descriptors are hidden (the omission comes from lock churn that is over in that time, and the refusal that remains is Unknown, never Gone); one read for a launcher whose descriptors are readable |
| `tego scan`, `tego agents` | `exe` and `environ` of every process of the user | **a live undumpable launcher is reported as an unreadable program** (`unreadable-program`, `permission`, its pid in `unreadable_program_pids`), as `ssh-agent`, a browser or a password manager already is; the snapshot is partial and `tego scan --check` exits unreadable unless `--allow-unreadable-programs`. Never omitted and never guessed not to be an agent: `tego scan` also prints, on stderr and only for a pid that is the proved lock holder of a live run (the proof `tego stop` makes), `pid N is the launcher of run R`, beside the count and with the exit code unchanged. A lock line alone names nothing: a program that wrote one could otherwise make itself disappear from the scan. The one exception is the dashboard, which holds `~/.tego/dashboard/lock` while it serves; a basic scan proves that lock as it proves a launcher's (`runlock.DashboardPID`: the kernel's lock table and the pid's start time) and leaves that pid out of the unreadable programs, so a running dashboard does not make `tego scan --check` exit 3. It proves who holds the lock, not that the holder is the real dashboard (a process of the user that takes the lock while no dashboard runs is left out too), which is why exit 0 never means that no agent runs. `tego agents` runs as root and reads it. |
| peer identification (`peer.Identify`: the ask broker, the operator socket, the forwarder's peers) | the connecting process's cgroup namespace (`ns/cgroup`) | an undumpable **peer** has no readable cgroup namespace. No launcher is a peer of any server that identifies: only `tego ask`, `approve`, `deny` and `tego-control` connect to a broker. Since 2026-11-22 `peer.Identify` proves from files that stay readable (the owner of `environ`, `status`'s uids and `CapPrm`) that a hidden namespace is hidden by the dumpable flag alone, and `peer.Refuse` judges that peer on everything else as any peer's (ADR 0100 (7), amended 2026-11-22), so the dashboard is undumpable and still answers. |
| the MCP relay's holder placement (`mcprelay.holderSearch`) | the descriptors of the processes in the run's cgroup | the launcher is not a member of the run's cgroup (the run's reaper kills that cgroup when the launcher dies, docs/ARCHITECTURE.md "Supervisor death"), so it is not searched; a client that is undumpable is placed by exclusion or refused, as the admission change above made it |
| the adoption's release and the adoption reaper (`adopterAlive`, `awaitRelease`) | the adopter's `stat` identity and a pidfd | works (`TestUndumpableLauncherIsAliveToStatus`: stat, `Process`, pidfd, signal 0) |
| the run's reaper and the build's helpers | the launcher's pidfd, inherited | works: a pidfd poll needs no `/proc` entry |

**What the agent's processes can still see of the launcher** (`TestMakeUndumpable`, from a child of
the undumpable process): `stat`, `status` (uids, capabilities, seccomp), `cmdline` (the contract path and flags; a value never is an
argument), `cgroup`, `comm`, `mountinfo`, the socket tables of `/proc/net` (addresses and inodes, not whose), and whatever a run's
own rules say of signalling it. It can no longer read `environ`, `mem`, `maps`, `fd`, `fdinfo`, `exe`, `cwd`, `root`, `ns/*`, `io`
or `syscall`, attach to it, read its memory with `process_vm_readv`, or take a descriptor with `pidfd_getfd`. The agent's own
processes stay dumpable.

**What stays open, said plainly.**

- **`tego-control serve` was dumpable; it is not since 2026-11-22.** It holds the sign-in token (also in a 0600 file the
  same user reads), its CSRF and acknowledgement keys, and it is the ask broker's operator peer, which the broker admitted only after reading the peer's `ns/cgroup`. This
  stood until then: inside an enforcing tier a governed agent is refused `ptrace`,
  `process_vm_readv`, `/proc/<pid>/mem` and `pidfd_getfd` toward a process outside its run, but a run with no Landlock domain
  (`tego watch` with no `--boundary`, `--observe`) on a Yama 0 host could attach to the dashboard and read its keys. Now
  `tego-control serve` is `Command.HoldsSecrets`: `mainWith` makes the process undumpable (`sys.MakeUndumpable`, with its
  read-back) before the command runs and it does not start when that fails (exit 125, `[undumpable]`), and the broker admits it
  by the peer's `SO_PEERCRED` uid, its pidfd and its cgroup path, which `/proc` keeps readable: the first of the three designs
  the ruling named. Why an agent in a run cannot pass it, what each reader of the dashboard's `/proc` needed, and the tests
  are in ADR 0100, "Amendment, 2026-11-22: the peer check admits an undumpable peer". The sign-in token alone still reaches nothing, since the loopback
  listener refuses a request whose socket was made inside a run (`peer/tcp.go`, `sock_diag`), which `/proc` does not hide.
- **The superblock proof on a btrfs subvolume.** `/proc/locks` prints `sb->s_dev` and `stat` the subvolume's anonymous
  device, so on btrfs (and bcachefs, overlayfs) the exact row never matches. A caller that cannot read the launcher's descriptors
  (no `CAP_SYS_PTRACE`) now takes the row for the lock file's inode and the launcher's pid when its device is the superblock
  device of the mount that holds the file: `statx` (`STATX_MNT_ID`, Linux 5.8) on the descriptor gives the mount id (fdinfo's `mnt_id:`), `/proc/self/mountinfo` gives that mount's
  `major:minor` (`sb->s_dev`), and the mount id is read again after the table to catch a move (`runlock.superblockProof`,
  `rowOnDevice`). It is allowed only to a caller that is not root (real or effective), holds neither `CAP_KILL` nor
  `CAP_SYS_PTRACE` in its effective or permitted set, and whose launcher's real, effective, saved and filesystem uids all equal the
  caller's uid (`signalsOnlyItself`). A root or capable caller never takes it: it keeps the exact device and the descriptors, which
  `CAP_SYS_PTRACE` reads. **Why a forged proof gives nothing.** Two subvolumes of one btrfs print one device and number inodes
  from 257 each, so the row alone is ambiguous: a user can create a subvolume, a file of inode N, and a lock line that names a
  victim pid holding a lock on its own inode N elsewhere. What such a forgery buys is a `tego stop` that signals the victim, an
  `ask`, `approve` or `deny` that connects to a socket the victim does not serve (the broker's own peer check still names the
  socket's server, and it is not the victim), and a status that calls a process a launcher. The signal goes only to a process
  whose four uids are the caller's, which the caller could already signal with `kill(2)`, and a caller that could signal more
  (`CAP_KILL`, root) is not given the shortcut. The residual is that a same-user process which can write a run directory (the agent
  cannot) can pose as the broker of a run; it is a same-user process with the user's own powers, and that stays as it was.
  `TestSignalsOnlyItself`, `TestSuperblockProof` (the gate, another device, pid, inode, no table, a mount that is not listed, a
  mount that moved) and the guest evidence below.
- **The caller the superblock proof does not serve (2026-11-24).** Root without `CAP_SYS_PTRACE` (Docker's default),
  a caller with `CAP_KILL`, and a caller that is not the launcher's user cannot read an undumpable launcher's descriptors and do not
  take the superblock row, so on a filesystem whose `/proc/locks` prints the superblock's device (btrfs, overlayfs, bcachefs) they read
  the run as launcher unknown, and `tego stop`, `ask`, `approve`, `deny` and `pause` refuse (exit 125) and signal nothing. This is
  a limit of what such a reader can prove, not a defect, and it is the price of the gate above: the row `(device, inode)` cannot
  tell the lock file from a file of another subvolume of the same filesystem that has the same inode number and is locked by
  some other process, and the lock line that names that process is written by the run's user. Reading the launcher's `mountinfo`
  does not separate them (a nested subvolume is not a mount). The reader now says exactly that: when the table lists the launcher's
  flock only under the superblock's device it names that device and why this caller does not take the row, and a caller that is
  refused every descriptor's `fdinfo` (root lists the directory) is told the descriptors are hidden from it instead of "no
  descriptor proves the run's flock". What proves it for such a caller is `CAP_SYS_PTRACE` (the descriptors), the launcher's own
  user (the row), or a filesystem whose two devices agree (the exact row: ext4, xfs, tmpfs). The launcher-answers design (the
  launcher passes its lock descriptor over the run's socket and the verifier reads the FLOCK row from the received descriptor's
  `fdinfo`) would prove it everywhere and needs a running, answering launcher, which is not the case a stop is wanted most. Guests: Fedora 7.0
  (6.19.10, btrfs `/home`), Ubuntu 25.10 (6.17) and Debian 13 (6.12) on a loop btrfs, with the capability removed by
  `setpriv --bounding-set`; ext4 on a loop file as the control.
- **A run started inside a run.** An undumpable process of a governed run cannot be read by the run's supervisor (the
  descriptors and working directory it needs to decide a file operation are hidden, GAPS C44), so it refuses that process's
  file operations fail-closed. A nested `tego run` that held itself undumpable was therefore refused at its first open ("chain
  anchor: permission denied") instead of at the seccomp listener (EBUSY), still exit 125 and the outer run untouched, but for a
  reason the person could not read. `run`, `watch` and `adopt` now check, before the hold and before anything is loaded, whether
  this process's cgroup path shows a run (`runscope.LooksGoverned`, the guard every other command reads) and refuse with
  "a run cannot start inside a run", naming the outer run (`cli.refuseNestedRun`, `TestARunCannotStartInsideARun`). Other
  secret-holding commands are not touched. The hold is not made earlier or later, and no secret is loaded while dumpable.
- **The window before the hold.** The kernel gives a process its environment at `exec`, so for the milliseconds the Go runtime
  and `main` take before dispatch the environment of a `tego run` is readable as before. Nothing a command reads later (a saved
  login, the key, a value) is in that window.
- **A process with `CAP_SYS_PTRACE`, root, the kernel, swap and a crash of the host** read the memory whatever the flag says; the
  flag also ends core dumps of the process, which is wanted. A debugger of the same user cannot attach to a `tego run` either;
  `sudo gdb -p` can.

**Verified** (this host, Linux 6.17, ext4, Yama `ptrace_scope` 1, as a user in an empty-home view): `internal/platform/sys`
(`TestMakeUndumpable`), `internal/cli` (`TestSecretHoldingCommandsAreExactlyThese`, `TestUndumpableBeforeAnyThingACommandDoes`,
`TestACommandThatCannotBeMadeUndumpableDoesNotRun`, the scope protocol's new
case), `internal/runlock` (`TestUndumpableLauncherProofReadsTheTableAgain`,
`TestUndumpableLauncherIsAliveToStatus`) and `internal/scan` (`TestScanSaysAnUndumpableProcessIsUnreadable`).
**Not proved:** a root-tier run's launcher (it is already undumpable after its first credential change and unchanged here) and a
kernel with `fs.suid_dumpable` 1 (both hosts measured had 2).

**Guest evidence for the review fixes** (Fedora cloud image, kernel 6.19.10, root and `/home` on btrfs subvolumes, Yama
`ptrace_scope` 0, SELinux enforcing, user `probe` uid 1000, no sudo in the probe; the retained logs are kept outside this repository). A real `tego run` at tier
landlock with an `fs.ask` entry, started and answered by the same user:

- **btrfs.** For the run's lock file `stat` says device 0:51 and `/proc/locks` prints 0:32, which is what `mountinfo` gives for the
  mount that holds it (`evidence/btrfs-lockdev.txt`). The launcher's `environ`, `mem`, `maps`, `fd` and `exe` are refused to the
  user, its `stat` is readable. This change's `tego status` shows the run with no "(launcher unknown)"; `tego ask` lists the ask,
  `tego deny` and `tego approve` answer the agent's two held writes (the first write fails, the second goes through), `tego stop`
  stops a run, and the dashboard's Stop (`tego-control serve`, signed in with its link, the confirm page's CSRF field, a POST with
  its own Origin) says "Stopped" and the launcher is gone. The reviewed build (`dc1faf6b1`) against the same kind of run: `status`
  shows "(launcher unknown)"; `ask`, `deny`, `approve` and `stop` exit 125 with "does not hold the run's lock"; the dashboard says
  "Not done: the run could not be stopped".
- **ext4** (a loop-mounted file in the same guest, the same flow): `/proc/locks`, `stat` and `mountinfo` print one device, and the
  old and the new build behave alike (status, ask, deny, approve, CLI and dashboard stop all work): the exact-device path is unchanged.
- **What a governed agent gets.** The agent walks its ancestors (the launcher, its parent, a login shell outside the run, `sshd`)
  and tries `environ`, `mem`, `maps`, a listing of `fd`, `PTRACE_ATTACH`, `process_vm_readv` and `pidfd_getfd`. Every ancestor
  refuses them (`EACCES`; `EPERM` for the attach and the read, on a guest whose Yama scope 0 would allow both to a dumpable process of
  the same user), the launcher and the dumpable login shell alike: Landlock's domain scoping and the supervisor's `pidfd_getfd`
  refusal, measured (`evidence/*-agent-probe.log`). A run with no Landlock domain was not run in the guest.
- The `runlock` test binary on that btrfs (`TestSuperblockProof`, `TestSignalsOnlyItself`, `TestUndumpableLauncherProofReadsTheTableAgain`,
  `TestUndumpableLauncherIsAliveToStatus`, `TestLockHolderProofForNonDumpableLauncher`) passes: the stand-in launcher is proved
  Alive by the superblock device through the real `statx`, `mountinfo` and `/proc/locks`.

## Proposed amendment 2026-11-03: preview or security boundary

Status: **proposed**. The owner decides the C50 options; SEC06 child binding and its compatibility fix are implemented.

**Compatibility consequence (implemented, SEC06 follow-up).** The first child-binding change introduced an
internal `<tego> __mcp_server …` exec that did not match an existing `<tego> mcp relay *` grant, so the shim failed
before it could register the child. Preserve that contract: no additional user grant or migration is required.
Before starting its child, the admitted shim registers its freshly created release socket inode and exact stage
vector. For an otherwise unlisted command, the supervisor may grant only this launcher's resolved image, that
whole vector, and the live child whose fd 3 is that socket while the authenticated shim still holds it. The relay
pins the child with a pidfd at that held exec; the subsequent registration must confirm the same child before its
server start can be consumed. A preexisting sibling cannot inherit the fresh socket. This adds no general
`__mcp_server` pattern or permission for another tego subcommand. Explicit command denies/asks, image/read floors,
live blocks, fences and gates still apply. The grant is named `exec.mcp-stage[<tego path>]` in the exec line and
`run_start.runtime_grants`; a plane pin covers the whole vector. At plane tiers the kernel keeps ownership of
the actual outcome: a pin refusal/kill stays refused and missing proof cannot claim the runtime grant. Tier 1
retains the existing copied-argv assurance
limit. The private protocol is v3 (v1/v2 refused); launcher and shims are rebuilt together. Integration covers the
constrained grant, a direct stage attempt and another tego subcommand, at Landlock and both plane tiers.
This compatibility decision does not choose either C50 option below or change the proposed status.

SEC06 closes C51's specific fork-then-exec theft: only the child registered before exec, still alive through its
retained pidfd, can consume the shim's start. C50 stays open. An agent allowed to attach to the shim or server can
inject bytes or duplicate a server socket with `pidfd_getfd`, bypassing decisions and their `mcp` record. Current
same-run process scoping is insufficient (`bpf/decide_control.h` admits same-run peers unless separately guarded).
`--preview` currently controls the dashboard navigation, not whether contracts can enable the relay.

**(a) Make the relay a security boundary.** Deny ATTACH authority over both shim and server before the agent can
reach them, throughout exec and for descendants that inherit server channels. Cover `PTRACE_ATTACH`/`SEIZE`,
`TRACEME`, `process_vm_*`, `/proc/<pid>/mem` and `pidfd_getfd`; refuse an already-traced shim or child and remove
inherited memory/socket descriptors. Preserve an authenticated pre-exec child handshake, fail closed on missing
hooks, and constrain alternate server spellings. A shim's `PR_SET_DUMPABLE=0` alone is insufficient: it is too late
for an existing tracer and an ordinary server exec resets dumpability.

| Tier | Candidate enforcement and compatibility cost |
|---|---|
| 1, Landlock + seccomp | Install irreversible run-wide seccomp denials for attach/memory-copy/`pidfd_getfd` syscalls before any agent task exists, and refuse protected proc-memory opens through the supervisor using pinned targets. Audit inherited FDs. A blanket denial is simpler than racing target-PID checks, but removes in-run debugging; shim-only seccomp does not constrain the attacker. |
| 2, cgroup | Keep the tier-1 denial on the fanotify fallback. In fmod_ret plane mode, extend the existing kernel-resolved ptrace hooks with protected shim/server identities and exec/fork lifecycle handling; reject existing tracing before admitting a shim. Fanotify alone cannot deny ptrace or socket copying. |
| 3, BPF LSM | Apply the same protected-task lifecycle in `ptrace_access_check` and `ptrace_traceme`; ATTACH checks also cover `pidfd_getfd`. Require the hooks, including server exec transitions and inherited channels, instead of relying on Yama or optional command guards. |

Validation requires design review, adversarial tests (Yama 0/1, pre-attached tracers,
socket theft, preexisting children, PID reuse, disconnects), capability/reporting changes and KVM kernel-matrix proof.
Tier-1 supervisor readability and debugger workflows
need explicit acceptance. A host Yama setting is an operational mitigation, not a portable per-run guarantee.

**(b) Retain the preview and state the limit.** Keep the present exposure, with the child-binding fix, and describe
C50, exact command matching and the scope of `--preview` in release notes and README **Known limits**. Make no
adversarial boundary claim for stdio `tools` rules. Keep a forbidden capability out of a reachable server, or use a
remote server whose direct endpoint the network policy refuses. The README and Unreleased notes now disclose the current behavior.

**Recommendation: (b)** for this release. SEC06 removes the demonstrated no-attach start theft without changing
process authority. Option (a) changes debugging and descriptor access across every tier and needs lifecycle and
kernel-matrix proof before a boundary claim is credible. Choosing (b) accepts the remaining C50 risk explicitly;
it neither closes C50 nor authorizes removing the preview label. No owner decision is recorded here.
