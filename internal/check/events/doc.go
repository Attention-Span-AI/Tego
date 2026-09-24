// SPDX-License-Identifier: Apache-2.0

// Package events renders raw events for tego events and --json output, over a whole run (TableOf, JSONOf) or
// as a ledger.Follower delivers a live run's lines (FollowTable, FollowJSON, for `tego events --follow`).
//
// Imports: internal/ledger, pkg/spec
// Must not import: internal/runtime
package events
