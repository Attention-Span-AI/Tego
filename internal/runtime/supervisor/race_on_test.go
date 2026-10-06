// SPDX-License-Identifier: Apache-2.0

//go:build race && (amd64 || arm64)

package supervisor

// raceEnabled is true in a -race build, where timing budgets measure the detector's instrumentation.
const raceEnabled = true
