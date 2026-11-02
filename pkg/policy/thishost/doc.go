// SPDX-License-Identifier: Apache-2.0

// Package thishost says which destinations are this host, however they are spelled: the one reading a live block
// (internal/liveblock), a net gate's `net to` rule (pkg/policy/gate) and the models[] guard (pkg/spec/agent) share, so a
// spelling closed for one is closed for all. It does no I/O: an address says some of this by itself, and what only the
// running host can tell comes in through Addrs, from a snapshot of its interfaces (internal/platform/hostaddr). A nil
// Addrs knows what the address says, which is all `compile --test` has.
//
// Imports: the standard library only.
// Must not import: anything else; pkg/spec, pkg/policy/gate and internal/liveblock all import it.
package thishost
