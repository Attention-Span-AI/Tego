// SPDX-License-Identifier: Apache-2.0

package web

import "github.com/attention-span-ai/tego/internal/guide"

func tourFactTitle(id string) string {
	switch id {
	case guide.StepCheck:
		return "Check"
	case guide.StepFind:
		return "Pick"
	case guide.StepRecord:
		return "Watch and Recorded"
	case guide.StepContract:
		return "Review"
	case guide.StepEnforce:
		return "Enforce"
	}
	return "Install"
}
