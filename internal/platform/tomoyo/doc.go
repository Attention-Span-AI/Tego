// SPDX-License-Identifier: Apache-2.0

// Package tomoyo checks the calling thread's TOMOYO domain and never-updated
// policy line afresh. No policy observation is kept between checks or runs.
// See ADR 0041's 2026-11-17 amendment for the limits of these observations.
//
// Imports: standard library, internal/platform/kernelconfig, golang.org/x/sys/unix
// Must not import: internal/runtime, internal/doctor, internal/policy, internal/check
package tomoyo
