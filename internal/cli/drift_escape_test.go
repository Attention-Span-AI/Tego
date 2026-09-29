// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/check/drift"
)

// TestContractLineEscapesLedgerHashes: run_start.contract_hash is ledger text a same-uid agent can edit and
// drift does not verify the chain, so the hash lines must not carry a control byte to the terminal.
func TestContractLineEscapesLedgerHashes(t *testing.T) {
	evil := "\x1b[2Jevilevilevilevil"
	for name, rep := range map[string]*drift.Report{
		"single":    {ContractHash: evil},
		"changed":   {ContractHash: evil, CurrentHash: "\x1b]0;x\a", HashChanged: true},
		"aggregate": {Hashes: []drift.HashCount{{Hash: evil, Runs: 1}, {Hash: "\rforged", Runs: 2}}},
	} {
		got := contractLine(rep)
		for _, b := range []byte(got) {
			if b < 0x20 || b == 0x7f {
				t.Errorf("%s: control byte %#x in %q", name, b, got)
			}
		}
	}
}
