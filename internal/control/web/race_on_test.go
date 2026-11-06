// SPDX-License-Identifier: Apache-2.0

//go:build race

package web

// raceEnabled is true in a -race build, where a timing figure measures the detector's instrumentation, not the code.
const raceEnabled = true
