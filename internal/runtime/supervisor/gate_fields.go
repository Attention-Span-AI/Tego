// SPDX-License-Identifier: Apache-2.0

package supervisor

// GateFields describes the decision actually reached before the notification
// was answered. Scores do not claim the kernel copied the same later argv/path.
type GateFields struct {
	Score                 *int   `json:"score,omitempty"`
	GateRule              string `json:"gate_rule,omitempty"`
	GateOutcome           string `json:"gate_outcome,omitempty"`
	GateFacts             string `json:"gate_facts,omitempty"`
	CompletionUnsupported bool   `json:"completion_unsupported,omitempty"`
}
