<!-- SPDX-License-Identifier: Apache-2.0 -->

# Square refund adapter square.refund.v1

Read-only source inspection on 2026-11-12, not a live server or payment test.
Repository: [square/square-mcp-server](https://github.com/square/square-mcp-server).
Pinned revision: `b276734fe2f1e6d4990fd99c2189c5d8d280a8b8`; package.json reports
`square-mcp-server` 0.1.2. `server.ts` reports MCP name square-mcp, version 1.0.0.
Neither label identifies the implementation by itself. No package was installed,
no server was started, no credentials were supplied and no project information
was sent. The exact public files were fetched by revision, not inferred from a
catalog. The tool registration and dispatch are verified by reading those bytes;
an actual tools/list response, installed dependency graph and remote behavior
remain unverified. This is not the separately hosted Square remote MCP service.

## Exact upstream interface and admitted subset

**A001.** The adapter MUST bind the public self-hosted server revision above,
tool `make_api_request`, configured Tego server label `square` (or the exact
bundle server label). It MUST NOT claim that a dedicated refund-named MCP tool
exists at this revision. Source: [server.ts](https://github.com/square/square-mcp-server/blob/b276734fe2f1e6d4990fd99c2189c5d8d280a8b8/server.ts).

**A002.** The upstream registration MUST be understood as these exact Zod fields
(descriptions omitted, no type or modifier omitted):

```typescript
{
  service: z.string(),
  method: z.string(),
  request: z.object({}).passthrough().optional()
}
```

`service` and `method` are required strings. `request` is an optional object
whose nested fields pass through; it is not a validated refund request schema.
This is a transcription of registration source, not a captured JSON Schema
tools/list response. Source: pinned server.ts, registration of make_api_request.

**A003.** The admitted dispatch MUST have literal lowercase `service:"refunds"`
and literal `method:"payment"`. The source capitalizes the service's first
character to select Refunds and dispatches method payment to POST `/v2/refunds`.
The adapter MUST refuse every other dispatch on this generic tool, including
`Refunds`, rather than accepting a server alias or returning none. Source:
[refunds.ts](https://github.com/square/square-mcp-server/blob/b276734fe2f1e6d4990fd99c2189c5d8d280a8b8/services/refunds.ts);
explicit narrower-profile decision, ADR 0151 decision 2.

**A004.** The admitted MCP envelope MUST satisfy A019 before selecting a tool.
For `make_api_request`, dispatch arguments MUST satisfy A020 before selecting
the refund payload in A005. The amount path MUST be
`/params/arguments/request/amount_money/amount`, currency path
`/params/arguments/request/amount_money/currency`. Source: explicit staged
adapter decision; pinned registration and handler.

**A005.** The admitted request object MUST be exactly `{amount_money,
idempotency_key,payment_id}` and amount_money exactly `{amount,currency}`.
All four leaves and the amount_money object MUST be present.
Unknown/nested/repeated/alternative money fields MUST refuse. Omitting payment_id MUST NOT enable an unlinked refund.
Source: explicit linked-refund-only decision, ADR 0151 decision 5.

**A006.** Amount MUST be a JSON integer token 1..9007199254740991 inclusive,
in the selected currency's minor units. Currency MUST be one B020 code,
literal uppercase ASCII. The maximum is narrower than signed 64 bits because
the pinned handler parses in JavaScript and JSON.stringify reserializes the
request. A numerically larger value MUST refuse even when an i64 can hold it.
Source: pinned handler; explicit no-rounding and positive refund decision.

**A007.** Idempotency_key MUST match `[A-Za-z0-9_-]{1,45}` and payment_id
`[A-Za-z0-9_-]{1,192}`. They are caller-supplied identifiers, not authenticated
business principals. Neither may be a safe recorded fact. Source: explicit
bounded ASCII subset decision; upstream request inventory.

**A008.** The implementation MUST account for this complete pinned upstream
RefundPaymentRequest inventory, even though v1 refuses every optional field:

| Field | Upstream type | Upstream required | Effect relevant to money; v1 treatment |
|---|---|---|---|
| idempotency_key | string | yes | Remote retry identity; require, local reuse refuses |
| amount_money | Money | yes | Submitted refund amount/currency; require both leaves |
| app_fee_money | Money | no | Changes developer contribution; refuse |
| payment_id | string | conditional | Selects original payment; v1 requires |
| destination_id | string | conditional | Can redirect to gift card or unlinked destination; refuse |
| unlinked | boolean | no | Changes linked refund into unlinked refund; refuse even false |
| location_id | string | conditional | Selects unlinked seller location; refuse |
| customer_id | string | conditional | Identifies customer for some unlinked destinations; refuse |
| reason | string | no | Free text, not a monetary override in inspected handler; refuse |
| payment_version_token | string | no | Optimistic concurrency and whether remote operation proceeds; refuse |
| team_member_id | string | no | Remote association; refuse |
| cash_details | DestinationDetailsCashRefundDetails | no | Cash recording, seller-supplied money/change; refuse |
| external_details | DestinationDetailsExternalRefundDetails | no | External refund type/source; refuse |

Money has optional amount of type integer and optional currency referencing
Currency; the generic Money inventory allows negative values in some contexts.
V1's required positive amount and closed currency list are explicit restrictions,
not claims about upstream schema defaults. DestinationDetailsCashRefundDetails
has required seller_supplied_money and optional read-only change_back_money,
both Money. DestinationDetailsExternalRefundDetails has required type and source
strings and optional source_id string. Source: exact
[type-map.ts RefundPaymentRequest entry](https://github.com/square/square-mcp-server/blob/b276734fe2f1e6d4990fd99c2189c5d8d280a8b8/utils/type-map.ts).

**A009.** Future upstream fields, including app_fee_allocations in the current
API documentation but absent from the pinned inventory, MUST refuse. The
adapter MUST NOT silently follow current web docs instead of its revision.
Source: version-pinning decision; [current API](https://developer.squareup.com/reference/square/refunds-api/refund-payment),
read 2026-11-12 (displayed API version 2026-09-16).

**A010.** Server ACCESS_TOKEN, base URL/environment and SQUARE_VERSION MUST be
trusted pinned configuration. The pinned config defaults to API version
2025-04-16 and the production connect.squareup.com host; v1 MUST pin these
explicitly rather than inherit ambient values. They select account, endpoint
and semantics. DISALLOW_WRITES may refuse writes but MUST NOT be treated as
the business cap. Source: pinned
[config.ts](https://github.com/square/square-mcp-server/blob/b276734fe2f1e6d4990fd99c2189c5d8d280a8b8/config.ts)
and server.ts; explicit configuration-binding decision.

**A011.** The adapter MUST NOT infer settlement, sufficient balance, refundable
remaining amount, seller currency support, eligibility, customer identity or
idempotency success from submitted fields. The server may reject a rule-allowed
call or report failure after a partial/uncertain effect. Source: ADR 0151 decisions 4, 5;
pinned POST handler forwards JSON and returns remote response text.

**A019.** The envelope stage MUST accept exactly a root object with fields
`{id,jsonrpc,method,params}`, jsonrpc string `"2.0"`, id a positive integer token
<=9007199254740991, method string `"tools/call"`, and params an object with
exactly `{arguments,name}`. Name MUST be a W005 label string; arguments MUST be
an object. Missing, unknown, wrongly typed or out-of-range fields in this stage
MUST yield `adapter.envelope`. This stage MUST NOT validate the fields inside
arguments. After global call grammar, limits and canonical checks and this
stage, any name other than `make_api_request` MUST yield none, regardless of
its arguments' shape beyond being an object. Source: explicit validation-boundary
decision resolving freeze review 1.

**A020.** On `make_api_request`, the dispatch-shape stage MUST require exactly
`{method,request,service}` inside arguments, with method and service strings and
request an object. Missing, unknown or wrongly typed fields at this boundary
MUST yield `adapter.missing`, `adapter.unknown` or `adapter.type` respectively.
Only after this shape passes MUST service/method values be compared with A003;
any other value MUST yield `adapter.dispatch` before inspecting the request's
contents. The payload stage MUST then validate only request and its descendants
against A005 through A007, with B053/B054 diagnostics. Missing parents MUST be
reported at the parent path; descendants of a missing or wrongly typed parent
MUST NOT create additional missing-field errors. Source: explicit validation-boundary
decision resolving freeze review 1.

## Exclusive topology admission

**A012.** The only target topology MUST be `trusted-stdio-worker-v1`: an immutable
local Square stdio worker outside the governed agent's process tree, owned by
the launcher, with exclusive channels terminating at the existing MCP relay.
The agent MUST reach those channels only through the admitted relay protocol.
The current in-run shim/server arrangement MUST NOT be labelled this topology.
Source: explicit target design decision under ADR 0151 decision 2.

**A013.** Admission MUST require the conjunction of: enforcing launched run;
available kernel mechanisms for every claimed restriction; authenticated run
peer; trusted worker identity/configuration; pinned node, code, dependencies
and schema; no agent write to these; no inherited/passed worker channel or
credential descriptor; no preexisting tracer; no agent read of worker secret
memory/environment/files; and no agent attach/memory-copy authority over the
worker or channel holders throughout fork/exec/descendant lifetime. Missing
evidence for any conjunct MUST refuse activation. Source: ADR 0151 decision 2;
explicit fail-closed admission predicate.

**A014.** The agent's kernel-enforced contract MUST deny direct Square/MCP/payment
API egress, alternate server invocations, host/proxy sockets and delegated
helpers that could carry the same request. This first profile MUST permit no
agent internet egress, and only the authenticated relay channel and explicitly
enumerated local control channels. Any additional external destination or
forwarding service MUST require a separately reviewed topology profile, rather
than an inference that it cannot tunnel. The trusted out-of-run worker alone may use its
separately scoped API authority. An exec name match or client configuration
alone MUST NOT establish exclusivity. Source: ADR 0007; ADR 0126 security argument;
explicit bypass-authority decision.

**A015.** Runtime admission MUST verify actual enforcement capabilities and
descriptor/process identity, not trust booleans supplied by the agent. Network,
file and process rules MUST keep alternate routes and worker mutation out of
reach. A host/root administrator remains trusted. Unknown enforcement or loss
of the required boundary MUST block more affected calls. Source: ADR 0151 decision 2.

**A016.** Direct hosted HTTP MCP, record-only and adopted runs, mutable workers,
agent-accessible credentials, permissive egress/host sockets, unreviewed proxy
routes and same-run attach capability MUST be unsupported by v1. Outside the
admitted topology documentation MUST say the rule covers only calls observed
on this relay, not all refund activity. Source: ADR 0151 decisions 2, 5.

**A017.** The inspected base MUST fail admission: its relay starts the server
inside the run, has no v1 argument validator/pinned worker/durable reservation
path, and does not establish every A013/A014 conjunct. Current enforcing-tier
pidfd_getfd imports already refuse; same-run ptrace is still conditionally
allowed. This specification MUST NOT close C50 or claim tier proof. Source:
stdio.go, supervisor/pty.go handlePidfdGetfd, bpf/decide_control.h; ADR 0151 context.

**A018.** A later integration MUST qualify kernel/tier process and channel
isolation, attempted alternate dispatch/routes, schema drift and real pinned
server parsing with harmless offline witnesses before enabling the profile.
No outbound payment test is authorized or needed for this specification job.
Source: ADR 0151 acceptance; explicit proof boundary decision.
