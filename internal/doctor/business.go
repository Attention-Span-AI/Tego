// SPDX-License-Identifier: Apache-2.0

package doctor

import "github.com/attention-span-ai/tego/pkg/spec/agent"

// BusinessRulesStatus reports product capability separately from kernel probes.
// Ready cannot become true until ADR 0152's conjunction is implemented and
// verified for the actual prepared run. No host probe or payment call is needed
// to establish that this build lacks the trusted worker and durable owner.
type BusinessRulesStatus struct {
	Profile string `json:"profile"`
	Ready   bool   `json:"ready"`
	Reason  string `json:"reason"`
}

func businessRulesStatus() BusinessRulesStatus {
	return BusinessRulesStatus{Profile: "trusted-stdio-worker-v1", Reason: agent.BusinessRulesUnavailable}
}
