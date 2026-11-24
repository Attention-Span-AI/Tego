<!-- SPDX-License-Identifier: Apache-2.0 -->

# Submitted refund rules

Business rules are not available for runs in this build. Contract validation can
pin one submitted-refund bundle. Run start and adoption refuse it with exit 125 because the
trusted worker, exclusive route and durable admission owner are not implemented.
Adoption needs root; business rules remain unavailable even as root.
After successful compilation, CLI run refuses before backend selection, orphan
sweeping, retention, anchor probing or capture construction. Machine configuration
and state-directory setup still precede compilation.
`tego doctor` reports the same missing capability. No tier, including the no-root
tier, can activate this profile. There is no warning-only protection mode.

The designed first action is Square's pinned public self-hosted server,
`make_api_request`, with `service: refunds` and `method: payment`. The intended
cap compares a submitted positive integer amount in minor units. USD 100.00 is
`10000`, without floating point arithmetic. Every other tool or dispatch of that
server must refuse; a refused batch must deliver none of its members. Direct
HTTP MCP, the legacy shim, cumulative caps, human approval, installed real
servers and dashboard switches remain unavailable.

## Contract declaration

The mapping belongs on the server entry, beside `tools:`. The bundle is a YAML
string containing canonical JSON, not a YAML rule map. Pin its SHA-256 and the
trusted worker manifest SHA-256. A manifest pin is not an installation or proof
of isolation. The following is a declaration template, not a runnable setup:

```yaml
mcp:
  - name: square
    command: [/opt/tego/workers/square/node, /opt/tego/workers/square/server.js]
    tools: {allow: [make_api_request]}
    business_rules:
      version: 1
      topology: trusted-stdio-worker-v1
      worker_digest: '<trusted manifest SHA-256, 64 lowercase hex>'
      bundle_sha256: '<bundle SHA-256, 64 lowercase hex>'
      bundle_json: '{"adapter":"square.refund.v1","rules":[{"codes":["USD"],"id":"currencies","kind":"currencies"},{"currency":"USD","id":"refund-cap","kind":"per_call","limit":"10000"}],"server":"square","version":1}'
```

The full contract needs `tier: bpflsm`, which requires root, and `record: full`. The compiler checks
the bundle with the evaluator's own decoder and preserves its digest in the
compiled table. Business worker commands receive no implicit agent exec grant,
so an explicit `exec.allow` entry is not described as redundant with this declaration.
It warns that activation is unavailable. Removing or changing a
bundle requires a newly reviewed contract and run. Empty or null cannot disable
an inherited restriction; duplicate server entries refuse rather than override.

A current attempted start says: `business rules unavailable: the root-owned
trusted worker, exclusive route and durable admission owner are not implemented;
this build refuses business-bearing runs on every tier`.

Once the rest of slice 1 is built, an over-cap call is intended to keep the
existing JSON-RPC error shape: code `-32001`, matching trusted request ID,
`error.data.tego.rule` and `reason`, with words such as `submitted USD 120.00
exceeds the USD 100.00 per-call limit (refund-cap)`. That positive/refusal path,
its durable record line and receipt are not implemented by contract validation.
Disclosure of the cap and condition is intentional; an agent can probe limits.
Raw arguments, payment IDs, idempotency keys and remote errors must not enter
those words or the record.

## Limits of the intended feature

- Tego does not put refund amount comparisons in the kernel. The relay evaluates
  them; Linux enforcement must make alternate routes unreachable before startup.
- This feature does not prevent refund loss through every tool or API.
- A person's approval or receipt verification does not prove refund success or
  run compliance.

Submitted fields do not attest account balances, refund eligibility or actual
money effects. A per-call cap permits splitting across calls. Other allowed
routes may perform equivalent work outside the named profile. Server or schema
changes require a new reviewed run. A missing reply leaves remote outcome
unknown. Starting a new run creates a new budget; this is not a cross-run quota.
The offline guest fixture must be labelled as a fixture and cannot qualify an
installed Square server. No payment credentials or live financial endpoint are
needed for its acceptance checks.
