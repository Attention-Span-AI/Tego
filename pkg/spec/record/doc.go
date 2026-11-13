// SPDX-License-Identifier: Apache-2.0

// Package record is the wire format of one run's audit trail: the frozen v1 schema of spec/record/v1 and its
// canonical JSON-lines codec.
//
// It owns Kind, Verdict, Authority, Source, Reason, Attribution, RunRef and Event, one payload struct per kind
// with the exact JSON names of docs/P0-DESIGN.md §3.2, and one deterministic encode/decode pair:
//
//   - MarshalLine writes the common fields in the fixed order v seq id prev ts mono_ns run agent pid tid cgroup
//     kind source rule verdict authority reason attribution, then the payload keys sorted (R1, R3), and sets
//     id = hex(sha256(line with id zeroed)) (R2). The bytes it returns are the bytes a ledger writes, minus the
//     "\n" terminator.
//   - Decode is tolerant: unknown keys never fail and land in Payload, only v is gated (R5); Validate applies the
//     semantic rules a writer must satisfy.
//   - VerifyLine recomputes a stored line's digest; Chain verifies a whole run's seq/prev/id links (I3, I4).
//
// The package does no I/O and decides nothing: it carries the verdict a caller already reached.
//
// Imports: standard library, pkg/spec/backend for typed run-end network counters, and pkg/spec/rfc3339 for the
// timestamp profile of spec/record/v1/CHAIN.md §3.
// Must not import: anything under internal/, yaml.
package record
