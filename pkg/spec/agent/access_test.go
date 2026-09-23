// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

func TestAccessSetABI(t *testing.T) {
	tests := []struct {
		bit  AccessSet
		name string
		abi  int
	}{
		{AccessExecute, "execute", 1}, {AccessWriteFile, "write_file", 1}, {AccessReadFile, "read_file", 1},
		{AccessReadDir, "read_dir", 1}, {AccessRemoveDir, "remove_dir", 1}, {AccessRemoveFile, "remove_file", 1},
		{AccessMakeChar, "make_char", 1}, {AccessMakeDir, "make_dir", 1}, {AccessMakeReg, "make_reg", 1},
		{AccessMakeSock, "make_sock", 1}, {AccessMakeFifo, "make_fifo", 1}, {AccessMakeBlock, "make_block", 1},
		{AccessMakeSym, "make_sym", 1}, {AccessRefer, "refer", 2}, {AccessTruncate, "truncate", 3},
		{AccessIoctlDev, "ioctl_dev", 5}, {AccessResolveUnix, "resolve_unix", 9},
	}
	seen := AccessSet(0)
	for _, tc := range tests {
		if tc.bit.MinABI() != tc.abi {
			t.Errorf("%s: MinABI=%d want %d", tc.name, tc.bit.MinABI(), tc.abi)
		}
		if tc.bit.String() != tc.name {
			t.Errorf("%s: String=%q", tc.name, tc.bit.String())
		}
		if tc.bit.ForABI(tc.abi-1) != 0 || tc.bit.ForABI(tc.abi) != tc.bit {
			t.Errorf("%s: ForABI gate wrong", tc.name)
		}
		if seen&tc.bit != 0 {
			t.Errorf("%s: bit reused", tc.name)
		}
		seen |= tc.bit
	}
	if seen != AccessAll {
		t.Errorf("AccessAll=%v but the table covers %v", AccessAll, seen)
	}
	if AccessSet(0).String() != "-" || AccessSet(0).MinABI() != 0 {
		t.Error("empty set rendering")
	}
	if got := AccessWriteSet.ForABI(1); got.Has(AccessRefer) || got.Has(AccessTruncate) || !got.Has(AccessWriteFile) {
		t.Errorf("ForABI(1) of the write set = %v", got)
	}
	if AccessWriteSet.MinABI() != 5 {
		t.Errorf("write set MinABI=%d", AccessWriteSet.MinABI())
	}
	if (AccessSet(1 << 30)).String() != "unknown" {
		t.Error("unknown bit rendering")
	}
}
