// SPDX-License-Identifier: Apache-2.0

//go:build race

package sys

// raceEnabled is true in a -race build, where timing pins measure the detector's instrumentation.
const raceEnabled = true
