# ADR 0127: Model routes, a run's model calls rerouted live to declared backends

Status: **accepted 2026-10-27**; built. Model routing sends an agent's model API calls to an approved backend, a company proxy, a model
server on this machine or another provider's compatible endpoint, and changes that while the run lives, both ways.
Builds on the forwarder and the live-overlay pattern of ADRs 0100, 0124 and 0126 §4.

## Context

A `capture: forwarder` run already sends every model request through Tego: the agent's SDK points at a loopback
listener (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, Codex's `config.toml`), and the forwarder speaks TLS to the one
upstream the `models[]` entry declares, rewriting Host and SNI and verifying that host's certificate. An operator who
wants the same agent's calls to go through the company's LLM gateway for one afternoon, to a local model server while
the network is down, or to a cheaper compatible provider, has to stop the run, edit the contract and start again,
losing the agent's session. The forwarder is the natural place to switch: it is outside the run, it already chooses
the upstream, and every request through it is a ledger line.

Three things must hold. **No free redirect:** a dashboard or a CLI that can send prompts, and the keys in their
headers, anywhere is an exfiltration tool for whoever reaches it. **The agent never chooses:** a prompt-injected agent
must not move its own traffic. **The person knows what travels:** a request's headers go with it, so whoever sends an
endpoint elsewhere must be told that a key the agent holds itself goes there too.

## Decision

### 1. Contract: `models[].routes` (agent-contract.md R32)

```yaml
capture: forwarder
models:
  - provider: anthropic
    host: api.anthropic.com
    port: 443
    routes:                       # the backends this endpoint may be sent to while a run lives
      - {name: corp, host: llm-proxy.corp.example, port: 8443}          # TLS, certificate checked for this host
      - {name: local, host: 127.0.0.1, port: 11434, tls: false}         # plaintext: loopback only
```

- Routes belong to the `models[]` entry they reroute, rather than a top-level `model_routes:`, because a person
  switches an *endpoint* (the one base URL the agent holds) and the provider, the derive parser and the HTTP policy
  stay that endpoint's. `route_to:` with a single target was rejected: a list lets a person move between several
  approved backends and back without a contract change.
- The endpoint itself is the route named `direct`; every run starts there. Names follow one rule
  (`^[a-z0-9-]{1,40}$`), `direct` excluded, unique in the entry.
- `tls` defaults to true (TLS with SNI and certificate verification for the route's host, the forwarder's own leg);
  `tls: false` is allowed only on a loopback host (`127.0.0.0/8`, the name `localhost` itself): a plaintext route off
  the machine would carry the prompts and any key in the clear. A name under `.localhost` is refused, since a resolver
  that does not apply RFC 6761 (glibc without systemd-resolved) sends it to DNS; and the forwarder holds the rule by
  address as well (§4).
- `Load` refuses (each naming the entry and the fix): routes without an explicit `capture: forwarder`; a route that is
  the endpoint itself; one backend declared twice; `tls: false` off loopback; two `models[]` entries of one authority
  when either declares routes. `Compile` refuses routes under `tego run --observe` (nothing would keep the agent from
  writing its own overlay) and where the machine lowered capture below the forwarder.
- Canonical bytes: `routes` is `omitempty`, so a contract without routes hashes as before
  (`TestContractHashUnchangedWithoutRoutes`).

### 2. The live overlay (`internal/modelroutes`)

`<ledger_root>/<run>/model-routes.json`: `{version: 1, run, serial, routes: [{model, route, by, at, serial}],
changes: [{serial, op: set|clear, model, route, by, at}], lost}`, where `model` is the endpoint's declared
`host:port`. It is the `mcp-tools.json` pattern copied (a leaf linking neither binary's other packages): a writers'
lock file, read-modify-write, atomic rename, mode 0600, read only when it is a regular file reached without a symlink,
owned by this user or root and not group- or other-writable; at most 256 routes and 256 changes kept. The run
directory is write-denied to every run at an enforcing tier (R6a, R10), so the agent cannot write it.

The file names routes; whether a name is declared is decided by the reader through the contract
(`pkg/policy/modelroute.Resolve`): a name the contract does not declare resolves to `direct` and is logged, so a
hand-edited file sends no request anywhere the contract did not name.

### 3. The pure decision (`pkg/policy/modelroute`)

`Resolve(model, live)` is the route an endpoint's next request takes; `Names(model)` the choices (direct first);
`Widens(from, to)` is true for a move to any route but `direct`, from anywhere else. It lives in `pkg/policy`, not
`internal/check`, for ADR 0126's reason: the forwarder (engine) uses it, and the engine and the read side never import
each other.

### 4. The forwarder (`internal/runtime/capture/forwarder/route.go`)

- A Manager whose contract declares any route holds one router for the run; a listener whose endpoint declares none
  never consults it (the option-off path is unchanged: `TestRouteOffPathUnchanged`).
- Each request of a routed endpoint chooses its route **first** (a `lstat` of the overlay, a reread when it moved), then
  the body, the approval hold, and the
  upstream leg. `direct` uses the listener's own upstream and leg, so a routed endpoint at `direct` forwards exactly as
  an unrouted one. Another route gets its own leg, built once per run: the listener's transport construction with SNI
  and certificate verification pinned to the route's host and the resolved-address policy (`validatedDial`), or
  plaintext for a loopback `tls: false` route. Host is the route's; path, query, body and every other header are
  forwarded as before.
- A request held for approval while its endpoint's route moved is not sent (503, "this model endpoint's route changed
  while the request waited for approval; send it again"): the person has just stopped sending that endpoint's requests
  where it was going, and the approval showed another destination. The refusal is a `net` line, verdict `refused`,
  reason `model-route-changed`, rule `models[<endpoint>].routes`, with the route it would have taken (R26: a mapped
  error is an event). A request no approval held goes by the route chosen when it arrived, as a response already streaming does; only the held case is refused.
- The approval card names where a request goes: on a route other than `direct` its target reads
  `<endpoint> via <route> (<backend>) <METHOD> <path>`. The coalescing key carries the route the request chose
  (`direct` included), so a repeat that arrives after a switch (an SDK retry with the same body and headers) is asked
  on its own, with a card naming its route, rather than joining an approval whose card showed another destination.
- A plaintext route's leg checks the address each connection reached: one off loopback is closed before a byte is
  written, whatever name led there.
- A CONNECT or upgrade the compiled proxy policy would serve is refused while the endpoint is off `direct`: a tunnel
  goes to the declared endpoint's address and would go around the chosen route. The refusal (403) is a `net` line,
  op `connect_tunnel` or `websocket`, verdict `refused`, reason `net-http`, rule `models[<endpoint>].routes`, with
  the route in force.
- The router also polls the overlay every 500 ms (`RoutePoll`), so a change is recorded while the agent is idle; it
  stops before the listeners close at the run's end. An overlay that is not trusted or not valid keeps the routes last
  read in force and is said once per state in the forwarder's log; any other read error (EMFILE, a short read) is
  retried on the next request or poll. A change line goes out through the listener serving its endpoint, whichever
  request or the poll read it: each listener has its own queue, so a line written through another could reach the
  ledger after that endpoint's requests by the new route. A listener that is closing takes no more lines; the line then
  goes through the listener whose request read the change (whose handler Close joins before its flush), or else is not
  written, since the closing endpoint serves no further request. Lines of one endpoint follow the serial order; lines of
  two endpoints served by two listeners may interleave in either order.
- The first read, when the forwarder binds the run, puts in force what the overlay already says, with a line for each
  endpoint it puts off `direct`, from the overlay's entry: a `tego route set` made between the run's directory
  appearing and the bind (the run is running from `ledger.Open` on) is recorded, not silently in force.
- The routes in force are compared before and after each reread: an endpoint whose route moved with no change to say
  so (the overlay removed, replaced by one whose serial went down, or naming an undeclared route) gets a line of its
  own, from the overlay's entry when it has one, or a revert to `direct` with serial 0. No request goes by a route no
  line put in force.
- A request already streaming finishes where it began; a change applies from the next request.

### 5. A request's headers go with it

A route moves the whole request. `copyHeader` forwards the credential headers as the agent sent them, so a key the
agent holds itself (`env.pass`) goes to the route's backend, whichever route is in force and however that backend is
reached (`TestRouteCarriesTheAgentsOwnKey`). A person trusts that backend with that key twice: on adding the route to
a contract, and on confirming the change, where `tego route set`'s y/N and the `/routes/preview` form say so.

### 6. Who may change a route

- `tego route list <run> [--json]`, `tego route set <run> <endpoint> <route> [--yes]`, `tego route clear <run>
  <endpoint>`: `<endpoint>` is the `host:port` (host alone for 443) or the provider when one entry has it. `set` to a
  route other than `direct` asks y/N unless `--yes`. Only declared routes are accepted.
- The dashboard's **Model routes** page (`/routes`, nav beside MCP tools) through `internal/control/routeact`:
  `State` (each endpoint, the route in force, who set it, the routes with their TLS and the requests by each, the
  change history), `Plan`/`Set` (a widening needs the preview-bound acknowledgement: an HMAC under the service's
  random key, domain `tego-route-ack-v1`, over the run, endpoint, route and the overlay file's sha256), `Clear`.
  Whether a change widens is decided again on the overlay under the writers' lock, in `Set` and in `tego route set`:
  a change made between the preview's read and the lock cannot turn a no-op into an unacknowledged widening.
- The per-route request counts come from one counter in the pure core (`modelroute.RequestCounter`), which the CLI
  and the service share, keyed by the line's own declared host and provider and the route's name and backend.
- **Every change, widening or not, is refused from inside a run** (CLI `refuseGoverned`, the service's
  `SelfGoverned`, and the dashboard's governed-peer check on every POST, ADR 0123). Unlike a live block, which an agent
  may place on itself, a revert is refused too: the agent never chooses its route, in either direction.

### 7. Record (minor 27, `MinorModelRoutes`)

- Every `ssl_request` of a routed endpoint carries `route {name, authority}` (`direct` included). `host` and
  `endpoint` stay the declared endpoint's, so derive, drift and budgets read the exchange as before.
- A change put in force is one `gap what=enforce`, source `forwarder`, why `model-route-changed`, with `model_route
  {model, route, authority, by, serial, at}` (`direct` for a revert), in serial order for each endpoint (§4).
- A held request refused because its route moved is a `net` line, reason `model-route-changed`, rule
  `models[<host:port>].routes`, with its `route` (§4). A tunnel refused off `direct` is a `net` line, reason
  `net-http`, the same rule, with the route in force. A change line found by comparison rather than by serial carries
  the overlay entry's serial, or 0 on a revert to `direct` no change numbered.
- Below 27 each is refused `[below-minor]`; malformed, `[model-route]`; misspelt, `[field-case]`
  (`spec/record/v1/fixtures/modelroute`). Nothing is written for an endpoint without routes.

## Security argument

(1) **Only approved backends.** The contract is the only list of places; the overlay, the CLI and the dashboard name a
route, never a host, and every reader resolves the name against the contract's copy. (2) **The agent cannot choose.**
The overlay is in the run directory the agent cannot write; `tego route` and the dashboard refuse callers inside a run;
the agent's base URL never changes, so nothing in the agent's reach selects a route. (3) **The person is told what
travels.** The check before a widening says the request's headers go with it (§5). (4) **TLS is the route's.** SNI and
certificate verification are pinned to the route's host; plaintext is allowed only to this machine's loopback. (5) **Every request says where it went** and every change
is a chained ledger line.

(6) **The agent cannot go around the forwarder to a backend.** An enforcing forwarder run guards each route's backend
as it guards the endpoint (`RuleTable.GuardedModels`): a direct connection there is refused whatever `net:` allows.

*Residuals, said plainly:* a route's backend sees the prompts, which is the point of routing, so a person who adds a
route to a contract is trusting that backend with them; it also sees the request's headers, so a key the agent holds
itself goes to every route the endpoint is moved to, and the core limits none of them (§5); a model server on loopback
is reached by the launcher as the user, so it is that user's server Tego trusts; a request already streaming, or still sending its body, is not cut by
a change; the agent can see that a different model answered (a route is not hidden from the agent's outputs); guarding
a route's backend refuses the agent every destination on that backend's port that `net.allow` does not admit, not only
loopback servers (under a `net:` section a guarded port refuses unknown destinations), so a route to
`llm-proxy.corp.example:8443` or `localhost:11434` also closes those ports to the agent's other traffic.

## What this does not cover

- A path prefix on a route (`https://gateway.example/anthropic/v1`): a route is host and port; the path is the
  agent's. A gateway that needs a prefix is not reachable by a route yet.
- Rewriting the request's model name or provider shape (an Anthropic-shaped request to an OpenAI-shaped backend):
  routes go between compatible endpoints; translation is not Tego's.
- A per-request or weighted choice (load balancing, fallback on error): one route per endpoint at a time, by a person.
- Saving a live route into the contract: a route lasts for the run; Change rules writes the contract.
- The Locked and Adjustable modes: a route change is gated by its own acknowledgement and governed check, on a
  Locked run too. The mode check is not built, so a person outside every run can still move a Locked run's endpoint to
  a declared route, with confirmation (*amended 2026-11-01*; docs/GAPS.md C39).

## Consequences

- An operator can move a running agent's model traffic between declared backends from the dashboard or the terminal
  without restarting it, and back, with each request and change in the ledger.
- `run_start.record_minor` rises to 27 on every run (the only change on the option-off path); a contract without
  routes runs exactly as before: no router, no new field, no new line.
- `tego` and `tego-control` are rebuilt together; a run started by an older `tego` ignores the overlay.
- `docs/p0/agent-contract.md` (R32), `spec/record/v1/README.md` (revision 27),
  `spec/agent/v0/agent.schema.json`, `docs/DASHBOARD.md` (Model routes), `docs/user/model-routes.md` describe it.

## Implementation notes

### 2026-10-27

- **Verified:** unit tests per package (contract validation and hash, the overlay leaf, the pure core, the forwarder's
  switch both ways with Host and route on the line, a plaintext loopback route through the production leg, an
  undeclared or untrusted overlay, a request held for approval whose route moved answered 503 and sent nowhere, the Manager's poll writing a change line with no request, the CLI and service refusals and acknowledgements,
  the page's preview and governed-peer refusal), `TestModelRoutesInChrome` at 1920x1080 and 390x844, light and dark,
  and an end-to-end run at tier landlock with three local upstreams (two TLS, one plaintext).
- **Hardening:** The held-request refusal is a ledger line and applies only to held requests; the
  widening is decided under the writers' lock (service and CLI); a replaced or removed overlay writes its lines and a
  transient read error is retried; plaintext routes are held to loopback by the connected address and `*.localhost`
  is refused; the approval card names the route; route backends are guarded; change lines go through the asking
  listener; per-route counts are keyed by the line's endpoint in one shared reader. Tests:
  `TestRouteMovedWhileHeldIsNotSent` (the line and the card), `TestRouteMovedWhileReadIsSentByItsChosenRoute`,
  `TestRouteLowerSerialOverlayIsRecorded`, `TestRouteTransientReadErrorIsRetried`,
  `TestPlaintextRouteDialsLoopbackOnly`,
  `TestWideningDecidedUnderTheLock`, `TestRouteSetRecheckedUnderTheLock`, `TestCountsKeyedByEndpoint`,
  `TestModelRoutesRefusedUnderObserve`, `TestModelRoutesRefusedUnderALoweredCapture`,
  `TestGuardedModelsHoldRouteBackends`, and the record fixtures `request-refused-route-moved`,
  `route-reverted-unnumbered`, `below-minor.reason`, `below-minor.rule`, `model-route.reason*`.
- **Not verified:** a real company proxy or a real model server (fake upstreams only); a root tier run; a route under a
  contract that also has `net.http` rules or `proxy:` (the HTTP policy runs before the route is chosen and is
  unchanged); Codex's `config.toml` path (its base URL is the listener's, so it
  follows the route as any SDK does, not run here).
- **Further fixes (same day):** The approval coalescing key carries the route
  (`TestRouteCoalescedRetryAfterASwitchGetsItsOwnApproval`); a tunnel refused off `direct` writes a `net` line
  (`TestRoutedTunnelRefusalIsRecorded`, under `net.proxy` with a CONNECT and a WebSocket upgrade); change lines go
  through the endpoint's listener, or the asking one once it is closing
  (`TestRouteChangeLineGoesThroughTheEndpointsListener`, which replaces the first asking-listener test);
  the first read writes a line for a route set before the bind (`TestRouteSetBeforeBindIsRecorded`); the plaintext
  loopback check is tested through `buildRouteTransport` with a resolver answering an address off this machine
  (`TestPlaintextRouteLegChecksLoopback`).

## Amendment 2026-11-01: the nav

The dashboard's side nav no longer lists Model routes by default. It is left out unless `tego-control serve --preview` is
given, so a first-time reader sees only the pages that
work for every run. The page itself is unchanged and answers at `/routes` as before; a link to it still opens
it. Where this record says "the nav's" link or item, read "the nav's, with `--preview`". docs/DASHBOARD.md ("Start it")
holds the flag.
