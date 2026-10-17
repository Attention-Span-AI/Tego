// SPDX-License-Identifier: Apache-2.0

package deputy

// The clone syscalls' numbers on aarch64, for the filter to decide (a number the filter matches, never a call).
const (
	sysClone  = 220
	sysClone3 = 435
)
