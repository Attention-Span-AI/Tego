// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package runtime

// liveAnyTier reports whether the launcher skips agent.LiveTierCheck in its Adjustable start checks (checkAdjustable).
// A product build never does: ADR 0125 decision 7 keeps Adjustable to tiers cgroup and bpflsm. A build with -tags
// tegotesthooks reads TEGO_TEST_LIVE_ANY_TIER instead (livefence_testhook.go).
func liveAnyTier() bool { return false }
