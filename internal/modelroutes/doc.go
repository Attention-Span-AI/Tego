// SPDX-License-Identifier: Apache-2.0

// Package modelroutes is the run's live model route overlay (ADR 0127): the file a person (through `tego route` or the
// dashboard's Model routes page) and the run's forwarder share. The overlay, <ledger_root>/<run>/model-routes.json,
// holds, per models[] endpoint (its declared host:port), the route a person put in force for the rest of the run; the
// forwarder stats it on every request and every 500 ms, sends the endpoint's next request by the route it reads, and
// writes one ledger line per change it put in force. No entry for an endpoint is its own route, direct.
//
// The file lives in the run's directory under the ledger root, which the agent cannot write (R6a, R10): a change is a
// person's, never the agent's. Writes are a read-modify-write under a lock file with an atomic rename (the
// internal/liveblock pattern, copied rather than imported, as internal/mcptools does, so this leaf links neither
// binary's other packages). The file names routes; whether a name is one the contract declares is the reader's check
// (pkg/policy/modelroute.Resolve), so a hand-edited file can never send a request anywhere the contract did not name.
//
// Imports: the standard library, golang.org/x/sys/unix and internal/platform/sys (descriptor leases, ADR 0023).
// Must not import: internal/runtime, internal/control, internal/liveblock, internal/mcptools, pkg/spec.
package modelroutes
