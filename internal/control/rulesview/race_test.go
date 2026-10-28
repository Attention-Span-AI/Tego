// SPDX-License-Identifier: Apache-2.0

//go:build race

package rulesview

// raceEnabled: the race detector slows everything several times over, so timing tests skip.
const raceEnabled = true
