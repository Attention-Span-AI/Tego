// SPDX-License-Identifier: Apache-2.0

// Package ask coordinates local human approvals. It authenticates each packet's
// kernel credentials and records a decision before returning it to the caller.
// It never continues a trapped syscall or performs the approved operation: the
// supervisor retains the original notification and completes it safely.
// The optional fixed-system owner-only profile requires initial-namespace root,
// forbids standing/alternate answers and carries typed actor or system attribution.
//
// Imports: standard library, internal/askclient, internal/platform/{peer,proc,sys}, internal/runscope, pkg/spec/askproto and record.
// Must not import: internal/control or the runtime facade.
package ask
