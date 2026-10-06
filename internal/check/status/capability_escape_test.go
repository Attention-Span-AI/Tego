// SPDX-License-Identifier: Apache-2.0

package status

import "testing"

// TestCapabilityLineEscapesLedgerText: the tier and the capability names come from run_start, which a
// same-uid agent can edit, and `status` does not verify the chain; the line reaches a terminal, so no control
// byte may survive it (limits-check-doctor-cli.md, Views: every human-readable view escapes ledger text).
func TestCapabilityLineEscapesLedgerText(t *testing.T) {
	line := CapabilityLine("\x1b[2Jevil", map[string]bool{"\x1b[31mcap": false, "\rforged\n": false})
	for _, b := range []byte(line) {
		if b < 0x20 || b == 0x7f {
			t.Fatalf("control byte %#x reaches the terminal in %q", b, line)
		}
	}
}
