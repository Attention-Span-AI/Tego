// SPDX-License-Identifier: Apache-2.0

// Package supplychain holds the supply-chain demo (README.md, RUNBOOK.md, demo.sh, the poisoned dependency,
// the two fake servers and the contract template) and, under the integration build tag, the tests that keep
// it honest: the filled contract compiles and holds the rules the README names, the protected side
// refuses the key and the sends and asks about the token while the tests stay green, demo.sh check names
// each failure, and reset restores the contract. It has no code of its own: the binary never imports it.
package supplychain
