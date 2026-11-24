// SPDX-License-Identifier: Apache-2.0

//go:build race

package rules

// raceEnabled: a race build runs each draft compile in a race-instrumented child that takes about a second to start
// (internal/control/draftcompile's racescale.go), so the tests that make hundreds of compiles one after another do a
// fraction of them there: the race detector gains nothing from the other rounds, which run in every other build.
const raceEnabled = true
