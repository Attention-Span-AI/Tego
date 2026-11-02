// SPDX-License-Identifier: Apache-2.0

// Package agents holds the copy-paste contracts in this directory and the test that compiles them. It has
// no code of its own: the binary never imports it. The README promises that every file here loads with
// `tego compile` with only warnings, and kill test 7 runs three of them, so a contract that stops compiling
// or stops saying what kill test 7 relies on fails here rather than in a user's first run. The price table the
// contracts' cost_usd budgets need, ../prices.example.yaml, is loaded here as tego loads one.
package agents
