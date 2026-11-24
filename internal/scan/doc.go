// SPDX-License-Identifier: Apache-2.0

// Package scan contains bounded process, program, project and settings observations and caller checks
// for basic and initial-root advanced snapshots. The CLI owns record cross-checks and persistent writes.
// Discovery group evidence requires verified root-owned account files and placement
// without group/other writes, checked through retained descriptors in both passes,
// equal bytes in two fresh read passes and
// matching descriptor/path identity and metadata. Root edits that leave both
// passes reading the same bytes, including fragmented reads within one timestamp
// tick, are outside its account-evidence guarantee. Membership changed after the
// scan remains a limit. See grouptrust for the rename-only proof assumption.
// It retains fact codes and typed paths, never argv, environment or file values.
// Imports: standard library, x/sys/unix, platform/sys, grouptrust, runscope, watch/sig, scan/catalog, scan/result, spec/identity.
// Must not import: runtime, policy, BPF, doctor, ledger, guide, control or CLI.
package scan
