// SPDX-License-Identifier: Apache-2.0

//go:build !race

package ledgerview

// raceEnabled: the race detector is off, so the allocation budgets run.
const raceEnabled = false
