// SPDX-License-Identifier: Apache-2.0

// Package capture captures model traffic and turns it into ssl_request/ssl_response events; chooses uprobe
// or forwarder per process and records a gap event when neither applies.
//
// This file is the seam: the producer contract every capture source satisfies (aliases of internal/runtime's
// own Source, Sink, RunRef and Gap, so a capture source is directly a runtime.Deps.Capture member), the
// mode selection of docs/p0/capture-derive.md §4, and the coverage report a run turns into gap events. The
// mechanisms themselves live in the subpackages.
//
// Nothing here decides network policy: a connection that went around the forwarder is refused by enforce's
// compiled net.allow and recorded as net verdict=refused, never as a capture gap (R38).
//
// Imports: internal/runtime/source, internal/runtime/capture/*, internal/ledger, pkg/spec
// Must not import: internal/check; internal/runtime or any engine package (TestCaptureLinksNoEngine)
package capture
