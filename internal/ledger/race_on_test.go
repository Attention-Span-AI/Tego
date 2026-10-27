// SPDX-License-Identifier: Apache-2.0

//go:build race

package ledger

// raceEnabled is true in a -race build, where a test over a million lines runs ten times slower.
const raceEnabled = true
