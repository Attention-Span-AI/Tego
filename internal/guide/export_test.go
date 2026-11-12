// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"testing"
	"time"
)

// SetSuggestBudget sets the learn step's read budget (suggestBudget) for one test.
func SetSuggestBudget(t *testing.T, d time.Duration) {
	prev := suggestBudget
	suggestBudget = d
	t.Cleanup(func() { suggestBudget = prev })
}
