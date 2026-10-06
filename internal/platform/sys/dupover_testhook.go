// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package sys

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// DupOverForTest dup3s src's file onto the number dst, closing whatever dst named: the plane fill's reuse
// cell (TEGO_TEST_PLANE_FILL_REUSE, enforce-plane R16) stages a held number that names another file this way.
// Only a tegotesthooks build has it; dst is a number another owner holds, which is the fault the cell
// stages, so nothing else may do this (ADR 0023 A7).
func DupOverForTest(src *FD, dst int) error {
	return src.Borrow(func(n int) error {
		if err := unix.Dup3(n, dst, unix.O_CLOEXEC); err != nil {
			return fmt.Errorf("dup3(%d, %d): %w", n, dst, err)
		}
		return nil
	})
}
