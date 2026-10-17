// SPDX-License-Identifier: Apache-2.0

package deputy

// The clone syscalls' numbers on x86_64, for the filter to decide (a number the filter matches, never a call).
const (
	sysClone  = 56
	sysClone3 = 435
)
