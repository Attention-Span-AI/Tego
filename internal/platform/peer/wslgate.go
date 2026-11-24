// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package peer

// wslRuleOn reports whether this build may answer Outside on a WSL machine (selfReads.Withheld, and with it the
// readiness hold: WSLGateHolds). In an ordinary build it is the constant true, and this function is the whole of the
// switch: there is no variable to set, no environment variable, flag, file or setting that is read, and so nothing a
// person, an agent or a program can do to a released binary turns the rule off or on for WSL. The relaxation it gives
// applies only where WSL shows two of its marks (selfHost.wslHoldsAt): on one mark every hold and restriction stays.
// It was the constant false until the guest rows that ADR 0100's amendment of 2026-11-19 (round 4) required before the
// switch had passed, and the amendment of the commit that turned it on names them. The builds that prove the rule in a
// guest carry the tegotesthooks tag and take wslgate_testhook.go instead, where the switch starts off and a test sets
// it (TestOrdinaryBuildCannotTurnTheWSLRuleOn, TestOrdinaryBuildOnTwoMarkWSL).
func wslRuleOn() bool { return true }

// nestedRuleOn reports whether this build may answer Outside outside WSL in a cgroup namespace that is not the
// kernel's first one (a container, a nested system), where the rule has run in no guest (selfHost.withheld). In an
// ordinary build it is the constant false, as wslRuleOn is, and for the same reasons; the proof's builds take
// wslgate_testhook.go.
func nestedRuleOn() bool { return false }
