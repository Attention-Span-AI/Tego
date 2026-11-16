// SPDX-License-Identifier: Apache-2.0

// Package bpflsm is tier 3, the BPF LSM tier (the minimal form of ADR 0024, docs/FEATURES.md): the
// decision plane (bpf/decide.bpf.c) in LSM mode over the tier-2 backend, never a second backend beside it.
// Tiers 2 and 3 enforce one semantics; tier 3 is tier 2 with the plane
// required in LSM mode, where tier 2 takes the best mode doctor selected or the fanotify fallback. New is the
// constructor; the run's Prepare, arming, fill and record are enforce/cgroup's.
//
// Imports: internal/bpf, internal/runtime/enforce/cgroup
// Must not import: landlock
package bpflsm
