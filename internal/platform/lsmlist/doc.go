// SPDX-License-Identifier: Apache-2.0

// Package lsmlist reads the active security-module list from the file the administrator names (the machine config's
// lsm.list_file) when the kernel's own two answers, lsm_list_modules(2) and /sys/kernel/security/lsm, cannot be read:
// a container under Docker's default profile, where the profile refuses the call, older kernels lack it and securityfs
// is not mounted. The list decides which modules' labels a held file open compares (ADR 0041 D2), so a file is
// believed only when it is the kernel's own bytes (a read-only bind of /sys/kernel/security/lsm) or what root wrote
// in this container's boot (an owner, a mode, a path and a boot id that nothing the run does can forge), and the task
// it is read for holds nothing that could rewrite it. Every check runs afresh on every read; nothing is kept.
// See ADR 0041's 2026-11-25 amendment for what a wrong list would let through.
//
// Imports: standard library, internal/platform/sys, internal/platform/tomoyo, golang.org/x/sys/unix
// Must not import: internal/runtime, internal/doctor, internal/policy, internal/check
package lsmlist
