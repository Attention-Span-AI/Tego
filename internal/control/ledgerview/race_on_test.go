// SPDX-License-Identifier: Apache-2.0

//go:build race

package ledgerview

// raceEnabled: the race detector's instrumentation changes how many objects the same code allocates (the first plain
// query's count is a few percent over the quarter-per-line budget in a race build and under it in every other), so the
// allocation budgets skip there.
const raceEnabled = true
