// SPDX-License-Identifier: Apache-2.0

package uprobe

import "testing"

// TestEarlyDataEntryPointsAreNotHooked pins capture-derive.md E32 as the stated P0 limitation it is: TLS 1.3
// early data goes through SSL_read_early_data and SSL_write_early_data, which no probe covers, so a library that
// exports them attaches only at the entry points R1 to R3 name. The limitation is stated in the spec; a probe
// added for them without a rule (and a test of its own) would change what capture records without saying so.
func TestEarlyDataEntryPointsAreNotHooked(t *testing.T) {
	t.Parallel()
	path := writeELF(t, elfOptions{Dynamic: map[string]uint64{
		SymWrite: 0x1100, SymRead: 0x1140,
		"SSL_write_early_data": 0x1180, "SSL_read_early_data": 0x11c0,
	}})
	b, err := readBinary(path)
	if err != nil {
		t.Fatalf("readBinary: %v", err)
	}
	for _, sym := range []string{"SSL_write_early_data", "SSL_read_early_data"} {
		if b.Has(sym) {
			t.Errorf("%s is read as a symbol to attach to; E32 says early data is uncovered", sym)
		}
	}
	for _, p := range probesFor(b) {
		if p.Symbol != SymWrite && p.Symbol != SymRead {
			t.Errorf("probe on %s, want only the R1 to R3 entry points of this library", p.Symbol)
		}
	}
}
