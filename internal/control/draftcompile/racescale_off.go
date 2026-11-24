// SPDX-License-Identifier: Apache-2.0

//go:build !race

package draftcompile

// raceScale is 1 in every build without the race detector: the deadlines are exactly their written values
// (racescale.go says why a race build scales them).
const raceScale = 1
