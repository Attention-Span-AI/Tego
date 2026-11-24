<!-- SPDX-License-Identifier: Apache-2.0 -->

# Business slice 1: owed in a guest

Status: acceptance instructions, not a passed suite. The trusted worker kit,
authenticated business bridge, journal/checkpoint and receipt projection are not
implemented at this head. These instructions cannot be executed as a positive
end-to-end test until those artifacts exist. Do not substitute protocol 3 or
an in-process evaluator test for the missing product path.

Use the pinned Ubuntu 25.10 / Linux 6.17 amd64 row with BPF LSM explicitly
active and the required decision plane actually working. Boot offline with at
most 3 GiB through the host's resource wrappers.
Use `kvm-run.sh --status <scratch>/business.status --log
<scratch>/business.console` and retain the guest kernel/build/boot evidence.
A status other than `guest 0`, a lost QEMU process or any required skip is not
a pass.

## Provision and establish admission

1. In the guest, provision a dedicated non-agent service UID, a root-owned
   immutable fixture manifest/install, the protected persistent state root and
   boot scheduler registry. Pin fixture code, Node/parser/dependencies, schema,
   endpoint, explicit Square-Version 2025-04-16 and synthetic credentials.
   The fixture must transcribe the `make_api_request` registration and
   refunds/payment dispatch of Square revision
   `b276734fe2f1e6d4990fd99c2189c5d8d280a8b8`. Its inventory must say that it
   reproduces service/method strings, optional passthrough request registration,
   capitalization dispatch, request fallback, JavaScript parse/stringify,
   POST /v2/refunds headers/body, write-disable, text result and isError shape.
   A copied fixture requires an offline equivalence witness against the pinned
   code. It must not attest an installed real server.
2. Start an independent offline HTTP sink outside the governed tree. Store its
   request count and exact body bytes separately from Tego's ledger. No live
   financial endpoint or real credential may be reachable.
3. Generate the canonical two-rule USD bundle in `docs/user/business-rules.md`
   and its real SHA-256; pin the fixture manifest SHA-256 in the contract. Use
   `tier: bpflsm`, `record: full`, no capture/model forwarder, no external
   network grants, one business server and a non-root agent. Start with a clean
   root-owned run ID/epoch once. A reconnect must never reinitialize that state.
4. Run `tego doctor --json` inside the guest. Expect a per-check report, with
   readiness only when all prerequisites hold. Start the actual CLI run and
   repeat checks on the prepared handles before agent release. Delete or make
   unknown each prerequisite in a separate fixture: expect exit 125 and zero
   agent release, worker submission and sink requests. On this current head,
   doctor says unavailable and the business run must always exit 125.

## Refund, exact bytes and refusal

5. Through the actual agent client -> authenticated business bridge -> product
   relay, complete the frozen initialize/initialized/tools/list exchanges from
   ADR 0152. Verify the schema on trusted worker pipes. Attempt a call before
   that sequence completes: expect refusal and zero sink requests.
6. Send this exact canonical call as content plus one LF, cap 10000 minor USD:

   ```json
   {"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"method":"payment","request":{"amount_money":{"amount":10001,"currency":"USD"},"idempotency_key":"over1","payment_id":"payment1"},"service":"refunds"},"name":"make_api_request"}}
   ```

   Expect matching ID, JSON-RPC error -32001, safe rule/reason and words saying
   USD 100.01 exceeds the USD 100.00 per-call limit. Expect zero worker writes,
   zero intents and zero sink requests. Retain the minor-32 refusal line.
7. Send the same canonical shape with ID 2, amount 9999 and key under1. Expect
   exactly one intent and checkpoint before one local write, then one offline
   POST and one correlated response. Compare the evaluator's call content
   byte-for-byte with the worker stdin capture excluding the single LF, not
   merely the decoded amount. Compare the handler's effective POST body with
   its pinned JavaScript parse/stringify witness. The receipt must say Guest
   fixture and describe submitted USD 99.99, not settled money.
8. Repeat the admitted key under1 with a fresh JSON-RPC ID, then reconnect and
   try it again. Expect refusal and still exactly one sink request. Try reusing
   a pending response ID with a fresh key: expect capacity/ID refusal before
   intent. A completed JSON-RPC ID is not the durable idempotency identity.

## Closed surface, races and uncertainty

9. Attempt a batch containing an otherwise valid refund, a tool-call
   notification, other tools, refunds.listPayment/getPayment, payments.create,
   disputes.accept, orders.batchGet, escaped/duplicate nested keys, exponent
   money, unsafe integers, resources/prompts and server-delegated requests.
   Expect zero additional writes or sink requests. Try protocol 3 (including
   Stage/C/S) and every HTTP entry method: expect refusal before forwarding.
10. Inject notifications/tools/list_changed and schema drift on the trusted
    worker channel. Expect readiness withdrawn for the rest of the run and all
    later calls refused. Forged agent S frames must never count as evidence.
11. Race an independent mcptools/liveblock writer against final recheck, intent
    and write under controlled barriers. A tightening acknowledged first must
    yield zero bytes; if an admission linearizes first, at most that one call
    writes and every later call refuses. Repeat across launcher processes.
12. Fill the worker pipe; cancel independently while admission holds the
    policy lock. Expect the fixed 1000 ms monotonic write bound, no deadlock,
    no retry and retained uncertain intent. Inject short write, fsync failure,
    checkpoint failure, journal-ahead state, wrong epoch, recording failure and
    lost response. Expect refusal/poisoning, retained evidence and no clean
    coverage seal. Run the reaper and sweeps on torn business evidence: bytes
    must remain unchanged; no truncation, zero state or replay send is allowed.
13. Probe direct IPv4/IPv6, TCP/UDP/DNS, local proxy/Unix sockets, alternative
    server names/paths, inherited/passed channels, proc memory/env/fd,
    ptrace/process_vm/pidfd_getfd, code/config/manifest mutation and owner death.
    Each independent bypass sink must observe zero requests. Kill the owner:
    the guardian must close/kill workers and no later submission may occur.
    Remove each protection separately and demonstrate that its intended
    assertion fails. Source inspection and a tier name do not replace this.
14. Read the shared CLI/receipt projection. Expect one refused over-cap call,
    one admitted submitted refund and classified local/remote observations
    without double counting phases. Missing outcome/seal means unknown. Older
    records mean not recorded, not zero. Report every unresolved case explicitly.
