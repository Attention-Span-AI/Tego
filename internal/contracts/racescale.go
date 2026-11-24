// SPDX-License-Identifier: Apache-2.0

//go:build race

package contracts

// raceScale multiplies this package's deadlines in a build with the race detector, and only there (racescale_off.go
// keeps them exactly in every other build). Measured on 2026-11-19: the compiler's own tests ran 3.7
// times slower under -race (pkg/spec/agent TestCompile*: 43.0 s, 158.8 s), and a builder preview, whose draft
// compile starts a race-instrumented child (about one second before it compiles anything), took 3.3 to 9.0 s against
// 0.05 to 0.19 s (internal/control/rules preview tests, three runs each). Ten puts the 3 s compilation budget at
// 30 s, more than three times the slowest request measured, and scales every deadline of the draft and helper compile
// path alike so their order is kept.
const raceScale = 10
