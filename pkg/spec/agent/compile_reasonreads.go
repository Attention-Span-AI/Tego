// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// This file is reason.reads as compile output (ADR 0077): whether tier 1's seccomp filter tells the supervisor of every
// read open of a run whose record mode keeps no read, so that a read the Landlock ruleset refuses under deny_read is
// a refused line, and the agent's harness learns from the reason file why its read failed. Without it such a refusal
// happens inside a syscall the filter never notified, and nothing above the engine can see it.

// ReasonSection is the contract's reason: section (ADR 0077).
type ReasonSection struct {
	// Reads is reason.reads; "" reads as auto.
	Reads ReasonReadsMode `yaml:"reads,omitempty"`
}

// ReasonReadsMode is reason.reads.
type ReasonReadsMode string

const (
	// ReasonReadsAuto, the default, is ADR 0077's measured default: off. It would be on for a run with a harness had
	// the measurement stayed inside the rule's bounds (at most 25 µs an open and 5 % on the offline Claude Code
	// workload); the workload grew more (ReasonReadWorkload), so auto notifies nothing and compile says so.
	ReasonReadsAuto ReasonReadsMode = "auto"
	// ReasonReadsOn notifies every read open at tier landlock, whatever the harness.
	ReasonReadsOn ReasonReadsMode = "on"
	// ReasonReadsOff never does: a read Landlock refuses under record: summary or off writes no line.
	ReasonReadsOff ReasonReadsMode = "off"
)

// ReasonReadCost and ReasonReadWorkload are what compile states reason reads cost: test/bench/read-notify's median
// per open, a read open told to the supervisor and continued against one the filter lets through, and its wall-time
// change of the offline Claude Code workload, from the run at load below 2 (ADR 0077 §Measurement, quiet2; the two
// loaded runs measured more).
const (
	ReasonReadCost     = "each read open about 17 µs more"
	ReasonReadWorkload = "the offline Claude Code workload 19 % slower"
)

// reasonReads settles RuleTable.ReasonReads from the contract's key.
func (k *compiler) reasonReads() {
	k.rt.ReasonReads = ReasonReadsAuto
	if k.c.Reason != nil && k.c.Reason.Reads != "" {
		k.rt.ReasonReads = k.c.Reason.Reads
	}
}

// ReadsNotifiedWhy is why a run of the table at tier t has tier 1's filter tell the supervisor of every read open or
// does not, one of the record.ReadsNotifiedWhy values (run_start.reads_notified): record: full notifies every open at
// every tier, an --observe run's included (its filter takes the record mode alone); a read gate, an fs.ask_read entry
// and held reads at the enforcing tiers they apply to; reason reads (ADR 0077) only at tier landlock, since a root
// tier's kernel record carries a refused read (ReadsNotifiedWhyKernel) and a run that enforces nothing refuses none.
func (rt *RuleTable) ReadsNotifiedWhy(t backend.Tier) string {
	switch {
	case rt == nil:
		return record.ReadsNotifiedWhyRecordsOnly
	case rt.Record == RecordFull:
		return record.ReadsNotifiedWhyFull
	case t != backend.TierLandlock && t != backend.TierCgroup && t != backend.TierBPFLSM:
		return record.ReadsNotifiedWhyRecordsOnly // observe enforces nothing; auto is no run's tier (AtTier places it)
	case rt.Gate.Has(gate.FSRead):
		return record.ReadsNotifiedWhyGate
	case rt.HasAskRead():
		return record.ReadsNotifiedWhyAskRead
	case rt.ReadsHeldAt(t):
		return record.ReadsNotifiedWhyHeld
	case t != backend.TierLandlock:
		return record.ReadsNotifiedWhyKernel
	case rt.ReasonReads == ReasonReadsOn:
		return record.ReadsNotifiedWhyReason
	}
	return record.ReadsNotifiedWhyReasonOff // off, or auto (the measured default)
}

// ReasonReadsAt reports whether a run of the table at tier t notifies every read open for the reason channel alone
// (ADR 0077): what nothing else in the table already notifies. It is never part of HoldsFSNotifications, so a decision
// plane keeps deciding a root tier's opens in the kernel.
func (rt *RuleTable) ReasonReadsAt(t backend.Tier) bool {
	return rt.ReadsNotifiedWhy(t) == record.ReadsNotifiedWhyReason
}

// ReasonReadsNotified is ReasonReadsAt the table's own tier: a run's table is placed at its tier (AtTier) before
// Prepare, which installs the filter's every-open arm for it (enforce-landlock R16).
func (rt *RuleTable) ReasonReadsNotified() bool { return rt != nil && rt.ReasonReadsAt(rt.Tier) }

// reasonReadsLine is compile's print of reason.reads (PrintRuleTable) for a table that can land at tier landlock:
// whether a read Landlock refuses there is recorded and at what cost, or why not, what turning it on costs and how.
// "" when another key already notifies every read or the table never lands at tier landlock.
func reasonReadsLine(rt *RuleTable) string {
	if !rt.mayLandAt(backend.TierLandlock) {
		return ""
	}
	switch rt.ReadsNotifiedWhy(backend.TierLandlock) {
	case record.ReadsNotifiedWhyReason:
		return "reads recorded at tier landlock (reason.reads: on): a read the Landlock ruleset refuses under deny_read " +
			"writes one refused line, which the reason file holds; " + ReasonReadCost + ", " + ReasonReadWorkload
	case record.ReadsNotifiedWhyReasonOff:
		return "reason-reads-off (reason.reads: " + string(rt.ReasonReads) + "): a read the Landlock ruleset refuses under " +
			"deny_read gets EACCES and writes no line under record: " + string(rt.Record) + ", so the reason file never holds " +
			"it; reason.reads: on records it, " + ReasonReadCost + ", " + ReasonReadWorkload
	}
	return ""
}
