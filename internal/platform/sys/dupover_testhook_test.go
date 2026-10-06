// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package sys

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestDupOverForTest: the plane reuse cell's hook puts src's file on another owner's number, which then names
// src's file; a closed src does nothing.
func TestDupOverForTest(t *testing.T) {
	src, victim := openNull(t), openNull(t)
	z, err := Own(unix.Open("/dev/zero", unix.O_RDONLY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if err := DupOverForTest(z, numOf(victim)); err != nil {
		t.Fatal(err)
	}
	if idOf(t, victim) != idOf(t, z) {
		t.Fatal("the victim's number does not name src's file after DupOverForTest")
	}
	_ = src.Close()
	if err := DupOverForTest(src, numOf(victim)); !errors.Is(err, ErrClosed) {
		t.Fatalf("DupOverForTest from a closed owner = %v, want ErrClosed", err)
	}
}
