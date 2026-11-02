// SPDX-License-Identifier: Apache-2.0

//go:build !race

package decide

// sweepStride is 1 without the race detector: a sampled sweep checks every generated table (race_on_test.go).
const sweepStride = 1
