<!-- SPDX-License-Identifier: Apache-2.0 -->

# Integration acceptance cases

These cases describe future integration tests. They have not run. The pure
vectors cannot establish authenticated provenance, durable continuity, queue
atomicity, human authority, kernel isolation or build integration.

| Case | Given | Required observation |
|---|---|---|
| E01 epoch substitution | The owner retains expected epoch e1 for run1 and receives the zero-total e2 snapshot in c28-epoch-continuity-external. | B062: reject before constructing a request. No evaluator call or delivery. The pure c28 answer alone is allow because it has no independent epoch witness. |
| E02 epoch recovery | Restore the authenticated e1 snapshot with current revision, totals and seen keys for the admitted run1/bundle/server. | B032/B040/B062: verify provenance and expected epoch before constructing the request; preserve totals/replay state across connections and evaluator restarts. An uncertain restore blocks the route. |
| E03 new run | Explicitly admit a new run2 with a newly authenticated e2 and zero totals. | B034/B062: permit construction of the new-run request; never label it continuity of run1. See c18-new-run-new-epoch for pure supplied state. |
| E04 approval digest | Two clients choose request-bytes concatenation and a canonical object wrapper for approval bindings. | W026: neither format is certified by v1. Approval remains disabled until a later protocol specifies exact bytes and known digests. The bundle and call digest formats in W003 remain fixed. |
| E05 waiting bound | One run has one outstanding evaluation and 15 waiting calls, including 3 human-held calls. | W017/W028: one more waiting call is admitted; the next refuses queue_full. Outstanding evaluation consumes no waiting slot. A held call keeps its waiting slot. |
| E06 host bound | Across runs there are 64 waiting calls, including holds, plus outstanding evaluations. | W017/W028: another waiting call refuses queue_full. Extra helpers cannot evade the shared count. |
| E07 active run bound | Sixteen runs have waiting/outstanding work; another admitted run is idle. | W017/W028: work for the idle run refuses queue_full until one active run has no waiting or outstanding work. Idle admission alone consumes no active-run slot. |
| E08 implementation agreement | Go live library, Rust standalone and Rust browser builds receive every vector and the same additional input corpus. | B063: compare complete results, including diagnostic choice, facts, asks, bindings, record projection and reservation. Any disagreement on any input fails the build. Go and Rust must each match every authored expected answer; agreement on a wrong answer is insufficient. The browser preview has no forwarding authority. |
| E10 hold transition | One outstanding evaluation returns ask while its run already has 16 waiting calls. | W028: refuse queue_full instead of creating a seventeenth waiting hold; no delivery or budget reservation. |
| E09 topology | Qualify the pinned worker/channel/credential boundary and every A013/A014 conjunct with harmless offline witnesses. | A018: owed in a guest. Current-base admission must refuse. No outbound payment call is required. |

For E05 through E07, counter inspection and admission happen atomically. These
are integration acceptance obligations, not timing or availability claims.
