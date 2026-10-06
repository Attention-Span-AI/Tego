// SPDX-License-Identifier: Apache-2.0

package sys

// InertForTest is an owner of n that never calls close(2): it is born owning and kept, so a test fake can hand
// out a *FD (the hot seams return the concrete type, ADR 0023 A11) without that fake's number ever being
// closed. It lends like any owner; Close and CloseNow mark it closed and close nothing. Only _test.go files
// call it (the lint of ADR 0023 C3, F4).
func InertForTest(n int) *FD {
	f := &FD{num: int32(n)}
	f.state.Store(stOwns | stKept)
	return f
}
