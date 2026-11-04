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
  decides each JSON-RPC message of a POST body the same way (a batch holding a refused or held `tools/call` is
  answered with errors for every member; *amended 2026-11-01*: a body refused unread, or one past 4 MiB, is recorded as
  such a stdio line is, one `mcp` line under rule `mcp[<name>].relay`), filters `tools/list` in a JSON or SSE response, and forwards the rest over
  TLS (http for an `http://` URL) to the declared URL. A GET event stream from the server passes unfiltered (it
  carries no client call). Only a POST body is decided, so a request by any other method that carries a body is
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
  the dashboard and `--yes` or a typed confirmation on the CLI, and is refused from inside any run. The Locked check
  this paragraph planned is not built: a Locked run's tool switches can still be loosened, by a person outside every
  run, with confirmation (*amended 2026-11-01*; docs/GAPS.md C39).
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
- `docs/adr/README.md`, `docs/p0/agent-contract.md` (R16b `mcp[].tools`), `spec/record/v1`,
  `spec/reason/REASON-CHANNEL.md`, `docs/DASHBOARD.md` and `docs/user/mcp-tools.md` describe it.

## Amendment 2026-11-01: the nav

The dashboard's side nav no longer lists MCP tools by default. It is left out unless `tego-control serve --preview` is
given, so a first-time reader sees only the pages that work for every run. The page itself is unchanged and answers at
`/mcp` as before; a link to it still opens it. Where this record says "the nav's" link or item, read "the nav's, with
`--preview`". docs/DASHBOARD.md ("Start it") holds the flag.

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
