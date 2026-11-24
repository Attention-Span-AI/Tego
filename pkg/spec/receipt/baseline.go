// SPDX-License-Identifier: Apache-2.0

package receipt

import "github.com/attention-span-ai/tego/pkg/spec/record"

// BaselineSummary discloses the complete recorded coverage and only recorded refusals.
// Entry counts may overlap when an action rule has several memberships.
type BaselineSummary struct {
	Evidence      *record.Baseline   `json:"evidence"`
	ContractHash  string             `json:"contract_hash"`
	EffectiveHash string             `json:"effective_hash"`
	Refusals      []BaselineRefusals `json:"refusals"`
}

// BaselineRefusals is an entry's count of refused record lines, not unique causation.
type BaselineRefusals struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
}
