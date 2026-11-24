// SPDX-License-Identifier: Apache-2.0

// Package bizrule evaluates the frozen spec/policy/bizrule/v1 business rules.
// Evaluation is deterministic over canonical bundle/request bytes and supplied
// state. It proposes reservations, never mutates state or authorizes delivery.
// The trusted relay must authenticate topology, state provenance and epoch
// continuity, serialize admissions, durably commit intent and compose current
// restrictions before delivery. An ask requires the separate approval protocol.
//
// Imports: pure standard-library packages only.
// Must not import: internal, file, network, environment, clock, randomness,
// synchronization or process packages. No goroutines or callbacks.
package bizrule
