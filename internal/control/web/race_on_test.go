// SPDX-License-Identifier: Apache-2.0

//go:build race

package web

// raceEnabled is true in a -race build, where a timing figure measures the detector's instrumentation, not the code.
const raceEnabled = true

// testRaceScale multiplies a test deadline that waits on a helper or a draft compile child, in a race build only: such
// a child is race-instrumented and starts in about a second (internal/contracts racescale.go has the measurements).
const testRaceScale = 10
