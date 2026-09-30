// SPDX-License-Identifier: Apache-2.0

//go:build !race

package anthropic

// raceEnabled is false without the race detector; see race_on_test.go.
const raceEnabled = false
