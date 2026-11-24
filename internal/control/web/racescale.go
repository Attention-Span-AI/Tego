// SPDX-License-Identifier: Apache-2.0

//go:build race

package web

// raceScale multiplies the deadlines of this package that wrap or race a helper's or a draft compile's (guideCompute,
// the server's write timeout, an answer's exchange), in a build with the race detector only (racescale_off.go keeps
// them exactly in every other build). It is the factor internal/contracts and internal/control/draftcompile scale
// theirs by (their racescale.go has the measurements): an outer deadline must stay longer than the inner one it wraps.
const raceScale = 10
