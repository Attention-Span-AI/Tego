// SPDX-License-Identifier: Apache-2.0

// Package rfc3339 reads a record line's timestamp: the RFC 3339 date-time profile of spec/record/v1/CHAIN.md §3,
// which the run record and the governance record share. time.Parse(time.RFC3339Nano) alone is looser than RFC 3339
// (its fallback takes comma fractions, one-digit hours, offset hour 24 and offset minute 60), so Parse checks the profile's shape first
// and only then hands the value to time.ParseInLocation with UTC, without consulting the host's
// local timezone (ADR 0146, "First finding").
//
// Imports: the standard library only.
// Must not import: anything under internal/ or pkg/ (a leaf, like pkg/spec/identity).
package rfc3339
