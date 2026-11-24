// SPDX-License-Identifier: Apache-2.0

//go:build !race

package rules

// raceEnabled: no race detector, so the compile-heavy tests run all their rounds.
const raceEnabled = false
