// SPDX-License-Identifier: Apache-2.0

// Package runstatus owns the versioned run teardown status and its strict JSON codec (ADR 0143).
// Empty scope or cgroup ID means unknown; such a status cannot assert removal.
//
// Imports: standard library, pkg/spec/identity.
// Must not import: internal packages.
package runstatus
