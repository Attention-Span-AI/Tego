// SPDX-License-Identifier: Apache-2.0

//go:build race

package anthropic

// raceEnabled is true under the race detector, which makes sync.Pool drop items at random and instruments
// allocations, so a TotalAlloc bound cannot be measured.
const raceEnabled = true
