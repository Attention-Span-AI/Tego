// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

// scanDropStepHook, set only by TestScanAdvancedDropEveryThread before it drops, runs at each point between
// dropScanPrivileges' all-thread changes, so that test can make the kernel create threads inside every gap of the
// transition instead of hoping the scheduler places them there. It is read on the dropping
// goroutine only, after the test set it on that goroutine.
var scanDropStepHook func(step string)

// scanDropBetweenSteps holds the drop at a named point while the test's hook runs.
func scanDropBetweenSteps(step string) {
	if scanDropStepHook != nil {
		scanDropStepHook(step)
	}
}
