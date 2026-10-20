// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"testing"
)

// TestBorrowsRefuseNoObject: a nil Program or Map is an error, and fn never runs on a number that is not
// there.
func TestBorrowsRefuseNoObject(t *testing.T) {
	fn := func(int) error { t.Fatal("fn ran without an object"); return nil }
	if err := ProgramFD(nil, fn); !errors.Is(err, errNoObject) {
		t.Fatalf("ProgramFD(nil) = %v, want errNoObject", err)
	}
	if err := MapFD(nil, fn); !errors.Is(err, errNoObject) {
		t.Fatalf("MapFD(nil) = %v, want errNoObject", err)
	}
}
