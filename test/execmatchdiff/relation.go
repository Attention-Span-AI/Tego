// SPDX-License-Identifier: Apache-2.0

package execmatchdiff

// DecisionState is the part of a decision that determines whether an exec may
// proceed. A none result with Final=false holds the staged argument read.
type DecisionState struct {
	Outcome, List string
	Final         bool
}

// HeldRefusal reports a refusal becoming a held incomplete read, never an admit.
func HeldRefusal(complete bool, before, after DecisionState) bool {
	return !complete && before.Outcome == "refused" && after.Outcome == "none" && !after.Final
}

// PotentialLoosening preserves the released refusal and staged-finality floors.
// HeldRefusal is classified separately, before this predicate is evaluated.
func PotentialLoosening(before, after DecisionState) bool {
	return before.Outcome == "refused" && after.Outcome != "refused" || !before.Final && after.Final && after.Outcome != "refused" || before.Outcome == "refused" && before.List == "deny" && after.Outcome == "refused" && after.List == "ask"
}
