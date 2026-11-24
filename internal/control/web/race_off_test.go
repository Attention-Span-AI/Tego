// SPDX-License-Identifier: Apache-2.0

//go:build !race

package web

// raceEnabled is true in a -race build, where a timing figure measures the detector's instrumentation, not the code.
const raceEnabled = false

// testRaceScale is 1 without the race detector (race_on_test.go).
const testRaceScale = 1
